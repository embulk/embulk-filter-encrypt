package org.embulk.filter.encrypt;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.io.BaseEncoding;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.TaskSource;
import org.embulk.spi.BufferAllocator;
import org.embulk.spi.Column;
import org.embulk.spi.ColumnVisitor;
import org.embulk.spi.DataException;
import org.embulk.spi.Exec;
import org.embulk.spi.FilterPlugin;
import org.embulk.spi.Page;
import org.embulk.spi.PageBuilder;
import org.embulk.spi.PageOutput;
import org.embulk.spi.PageReader;
import org.embulk.spi.Schema;
import org.embulk.util.config.Config;
import org.embulk.util.config.ConfigDefault;
import org.embulk.util.config.ConfigMapper;
import org.embulk.util.config.ConfigMapperFactory;
import org.embulk.util.config.Task;
import org.embulk.util.config.TaskMapper;
import org.embulk.util.snakeyaml.EmbulkYamlTagResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.nio.charset.StandardCharsets.UTF_8;

public class EncryptFilterPlugin
        implements FilterPlugin
{
    public enum Algorithm
    {
        AES_256_CBC("AES/CBC/PKCS5Padding", "AES", 256, true, "AES", "AES-256", "AES-256-CBC"),
        AES_192_CBC("AES/CBC/PKCS5Padding", "AES", 192, true, "AES-192", "AES-192-CBC"),
        AES_128_CBC("AES/CBC/PKCS5Padding", "AES", 128, true, "AES-128", "AES-128-CBC"),
        AES_256_ECB("AES/ECB/PKCS5Padding", "AES", 256, false, "AES-256-ECB"),
        AES_192_ECB("AES/ECB/PKCS5Padding", "AES", 192, false, "AES-192-ECB"),
        AES_128_ECB("AES/ECB/PKCS5Padding", "AES", 128, false, "AES-128-ECB");

        private final String javaName;
        private final String javaKeySpecName;
        private final int keyLength;
        private final boolean useIv;
        private String[] displayNames;

        Algorithm(String javaName, String javaKeySpecName, int keyLength, boolean useIv, String... displayNames)
        {
            this.javaName = javaName;
            this.javaKeySpecName = javaKeySpecName;
            this.keyLength = keyLength;
            this.useIv = useIv;
            this.displayNames = displayNames;
        }

        public String getJavaName()
        {
            return javaName;
        }

        public String getJavaKeySpecName()
        {
            return javaKeySpecName;
        }

        public int getKeyLength()
        {
            return keyLength;
        }

        public boolean useIv()
        {
            return useIv;
        }

        @JsonCreator
        public static Algorithm fromName(String name)
        {
            for (Algorithm algo : EnumSet.allOf(Algorithm.class)) {
                for (String n : algo.displayNames) {
                    if (n.equals(name)) {
                        return algo;
                    }
                }
            }
            throw new ConfigException("Unsupported algorithm '" + name + "'. Supported algorithms are AES-256-CBC, AES-192-CBC, AES-128-CBC.");
        }

        @JsonValue
        @Override
        public String toString()
        {
            return displayNames[displayNames.length - 1];
        }
    }

    public enum Encoder
    {
        BASE64("base64", BaseEncoding.base64()),
        HEX("hex", BaseEncoding.base16());

        private final BaseEncoding encoding;
        private final String name;

        Encoder(String name, BaseEncoding encoding)
        {
            this.name = name;
            this.encoding = encoding;
        }

        public String encode(byte[] bytes)
        {
            return encoding.encode(bytes);
        }

        @JsonCreator
        public static Encoder fromName(String name)
        {
            EnumSet<Encoder> encoders = EnumSet.allOf(Encoder.class);
            for (Encoder encoder : encoders) {
                if (encoder.name.equals(name)) {
                    return encoder;
                }
            }
            throw new ConfigException(
                    String.format("Unsupported output encoding '%s'. Supported encodings are %s.",
                                  name,
                                  encoders.stream().map(Encoder::toString).collect(Collectors.joining(", "))));
        }

        @JsonValue
        @Override
        public String toString()
        {
            return name;
        }
    }

    public enum KeyType
    {
        INLINE,
        S3;

        @JsonCreator
        public static KeyType of(String value)
        {
            return KeyType.valueOf(value.toUpperCase());
        }

        @Override
        @JsonValue
        public String toString()
        {
            return super.toString().toLowerCase();
        }
    }

    public interface PluginTask
            extends Task
    {
        @Config("algorithm")
        public Algorithm getAlgorithm();

        @Config("output_encoding")
        @ConfigDefault("\"base64\"")
        public Encoder getOutputEncoding();

        @Config("key_type")
        @ConfigDefault("\"inline\"")
        KeyType getKeyType();

        @Config("key_hex")
        @ConfigDefault("null")
        public Optional<String> getKeyHex();

        public void setKeyHex(Optional<String> key);

        @Config("iv_hex")
        @ConfigDefault("null")
        public Optional<String> getIvHex();

        public void setIvHex(Optional<String> iv);

        @Config("aws_params")
        @ConfigDefault("null")
        public Optional<AWSParams> getAWSParams();

        @Config("column_names")
        public List<String> getColumnNames();
    }

    public interface AWSParams extends Task
    {
        @Config("region")
        public String getRegion();

        @Config("access_key")
        public String getAccessKey();

        @Config("secret_key")
        public String getSecretKey();

        @Config("bucket")
        public String getBucket();

        @Config("path")
        public String getPath();
    }

    private static final ConfigMapperFactory CONFIG_MAPPER_FACTORY = ConfigMapperFactory.builder().addDefaultModules().build();
    static final ConfigMapper CONFIG_MAPPER = CONFIG_MAPPER_FACTORY.createConfigMapper();
    private static final TaskMapper TASK_MAPPER = CONFIG_MAPPER_FACTORY.createTaskMapper();

    private static final Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), new EmbulkYamlTagResolver());
    private static final Logger log = LoggerFactory.getLogger(EncryptFilterPlugin.class);

    @Override
    public void transaction(ConfigSource config, Schema inputSchema,
            FilterPlugin.Control control)
    {
        final PluginTask task = CONFIG_MAPPER.map(config, PluginTask.class);

        validateAndResolveKey(task, inputSchema);

        control.run(task.toTaskSource(), inputSchema);
    }

    public Map<String, String> retrieveKey(final String bucket, final String path, final AmazonS3 client)
    {
        S3Object fullObject = null;

        try {
            fullObject = client.getObject(new GetObjectRequest(bucket, path));
            if (fullObject == null) {
                throw new ConfigException("S3 key file is not enabled to be retrieved");
            }
            return (Map<String, String>) yaml.load(fullObject.getObjectContent());
        }
        catch (AmazonServiceException e) {
            // The call was transmitted successfully, but Amazon S3 couldn't process
            // it, so it returned an error response.
            if (e.getErrorType().equals(AmazonServiceException.ErrorType.Client)) {
                // HTTP 40x errors. auth error, bucket doesn't exist, etc. See AWS document for the full list:
                // http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
                if (e.getStatusCode() != 400
                        || "ExpiredToken".equalsIgnoreCase(e.getErrorCode())) {
                    throw new ConfigException(e);
                }
            }
            throw e;
        }
        catch (ClassCastException e) {
            throw new ConfigException("S3 key file content is unexpected format");
        }
        finally {
            // To ensure that the network connection doesn't remain open, close any open input streams.
            if (fullObject != null) {
                try {
                    fullObject.close();
                }
                catch (IOException e) {
                    log.warn("Failure to close S3 Object input stream", e);
                }
            }
        }
    }

    public AmazonS3 newS3Client(final AWSParams awsParams)
    {
        AWSCredentialsProvider awsCredentialsProvider = new AWSCredentialsProvider()
        {
            @Override
            public AWSCredentials getCredentials()
            {
                return new BasicAWSCredentials(awsParams.getAccessKey(), awsParams.getSecretKey());
            }

            @Override
            public void refresh()
            {
            }
        };

        try {
            return AmazonS3ClientBuilder.standard()
                    .withRegion(awsParams.getRegion())
                    .withCredentials(awsCredentialsProvider)
                    .build();
        }
        catch (SdkClientException e) {
            throw new ConfigException(e);
        }
    }

    private void validateAndResolveKey(PluginTask task, Schema schema) throws ConfigException
    {
        switch (task.getKeyType()) {
            case INLINE:
                if (!task.getKeyHex().isPresent()) {
                    throw new ConfigException("Field 'key_hex' is required but not set");
                }
                if (task.getAlgorithm().useIv() && !task.getIvHex().isPresent()) {
                    throw new ConfigException("Algorithm '" + task.getAlgorithm() + "' requires initialization vector. Please generate one and set it to iv_hex option.");
                }
                else if (!task.getAlgorithm().useIv() && task.getIvHex().isPresent()) {
                    log.warn("Algorithm '" + task.getAlgorithm() + "' doesn't use initialization vector. iv_hex is ignored");
                }
                break;
            case S3:
                if (!task.getAWSParams().isPresent()) {
                    throw new ConfigException("AWS Params are required for S3 Key type");
                }
                AWSParams params = task.getAWSParams().get();
                AmazonS3 s3Client = newS3Client(params);
                Map<String, String> keys = retrieveKey(params.getBucket(), params.getPath(), s3Client);

                String key = keys.get("key_hex");
                if (isNullOrEmpty(key)) {
                    throw new ConfigException("Field 'key_hex' is required but not set");
                }
                String iv = keys.get("iv_hex");
                if (task.getAlgorithm().useIv() && isNullOrEmpty(iv)) {
                    throw new ConfigException("Algorithm '" + task.getAlgorithm() + "' requires initialization vector. Please generate one and set it to iv_hex option.");
                }
                else if (!task.getAlgorithm().useIv() && !isNullOrEmpty(iv)) {
                    log.warn("Algorithm '" + task.getAlgorithm() + "' doesn't use initialization vector. iv_hex is ignored");
                }
                task.setKeyHex(Optional.of(key));
                if (!isNullOrEmpty(iv)) {
                    task.setIvHex(Optional.of(iv));
                }
                break;
            default:
                throw new ConfigException(String.format("Key type [%s] is not supported", task.getKeyType().toString()));
        }

        // Validate Cipher
        try {
            getCipher(Cipher.ENCRYPT_MODE, task);
        }
        catch (Exception e) {
            throw new ConfigException(e);
        }

        // validate column_names
        for (String name : task.getColumnNames()) {
            schema.lookupColumn(name);
        }
    }

    private Cipher getCipher(int mode, PluginTask task)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException
    {
        Algorithm algo = task.getAlgorithm();

        byte[] keyData = BaseEncoding.base16().decode(task.getKeyHex().get());
        SecretKeySpec key = new SecretKeySpec(keyData, algo.getJavaKeySpecName());

        if (algo.useIv()) {
            byte[] ivData = BaseEncoding.base16().decode(task.getIvHex().get());
            IvParameterSpec iv = new IvParameterSpec(ivData);

            Cipher cipher = Cipher.getInstance(algo.getJavaName());
            cipher.init(mode, key, iv);
            return cipher;
        }
        else {
            Cipher cipher = Cipher.getInstance(algo.getJavaName());
            cipher.init(mode, key);
            return cipher;
        }
    }

    @Override
    public PageOutput open(TaskSource taskSource, final Schema inputSchema,
            final Schema outputSchema, final PageOutput output)
    {
        final PluginTask task = TASK_MAPPER.map(taskSource, PluginTask.class);

        final Cipher cipher;
        try {
            cipher = getCipher(Cipher.ENCRYPT_MODE, task);
        }
        catch (Exception ex) {
            throw new ConfigException(ex);
        }

        final int[] targetColumns = new int[task.getColumnNames().size()];
        int i = 0;
        for (String name : task.getColumnNames()) {
            targetColumns[i++] = inputSchema.lookupColumn(name).getIndex();
        }

        return new PageOutput() {
            private final PageReader pageReader = getPageReader(inputSchema);
            private final PageBuilder pageBuilder = getPageBuilder(Exec.getBufferAllocator(), outputSchema, output);
            private final Encoder encoder = task.getOutputEncoding();

            @Override
            public void finish()
            {
                pageBuilder.finish();
            }

            @Override
            public void close()
            {
                pageBuilder.close();
            }

            private boolean isTargetColumn(Column c)
            {
                for (int i = 0; i < targetColumns.length; i++) {
                    if (c.getIndex() == targetColumns[i]) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public void add(Page page)
            {
                pageReader.setPage(page);

                while (pageReader.nextRecord()) {
                    inputSchema.visitColumns(new ColumnVisitor() {
                        @Override
                        public void booleanColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setBoolean(column, pageReader.getBoolean(column));
                            }
                        }

                        @Override
                        public void longColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setLong(column, pageReader.getLong(column));
                            }
                        }

                        @Override
                        public void doubleColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setDouble(column, pageReader.getDouble(column));
                            }
                        }

                        @Override
                        public void stringColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else if (isTargetColumn(column)) {
                                String orig = pageReader.getString(column);
                                byte[] encrypted;
                                try {
                                    encrypted = cipher.doFinal(orig.getBytes(UTF_8));
                                }
                                catch (BadPaddingException ex) {
                                    // this must not happen because PKCS5Padding is always enabled
                                    throw new DataException(ex);
                                }
                                catch (IllegalBlockSizeException ex) {
                                    // this must not happen because always doFinal is called
                                    throw new DataException(ex);
                                }
                                String encoded = encoder.encode(encrypted);
                                pageBuilder.setString(column, encoded);
                            }
                            else {
                                pageBuilder.setString(column, pageReader.getString(column));
                            }
                        }

                        @Override
                        public void timestampColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                setTimestampToPageBuilder(pageBuilder, column, getTimestampFromPageReader(pageReader, column));
                            }
                        }

                        @Override
                        public void jsonColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setJson(column, pageReader.getJson(column));
                            }
                        }
                    });
                    pageBuilder.addRecord();
                }
            }
        };
    }

    @SuppressWarnings("deprecation")
    private static PageBuilder getPageBuilder(final BufferAllocator bufferAllocator, final Schema schema, final PageOutput output)
    {
        if (HAS_EXEC_GET_PAGE_BUILDER) {
            return Exec.getPageBuilder(bufferAllocator, schema, output);
        }
        else {
            return new PageBuilder(bufferAllocator, schema, output);
        }
    }

    @SuppressWarnings("deprecation")
    private static PageReader getPageReader(final Schema schema)
    {
        if (HAS_EXEC_GET_PAGE_READER) {
            return Exec.getPageReader(schema);
        }
        else {
            return new PageReader(schema);
        }
    }

    @SuppressWarnings("deprecation")
    public Instant getTimestampFromPageReader(final PageReader pageReader, final Column column)
    {
        if (HAS_GET_TIMESTAMP_INSTANT_COLUMN) {
            return pageReader.getTimestampInstant(column);
        }
        else if (HAS_GET_TIMESTAMP_COLUMN) {
            return pageReader.getTimestamp(column).getInstant();
        }
        else {
            throw new IllegalStateException(
                    "Neither PageReader#getTimestamp(Column) nor PageReader#getTimestampInstant(Column) found.");
        }
    }

    @SuppressWarnings("deprecation")
    private static void setTimestampToPageBuilder(final PageBuilder pageBuilder, final Column column, final Instant instant)
    {
        if (HAS_SET_TIMESTAMP_INSTANT) {
            pageBuilder.setTimestamp(column, instant);
        }
        else if (HAS_SET_TIMESTAMP_TIMESTAMP) {
            pageBuilder.setTimestamp(column, org.embulk.spi.time.Timestamp.ofInstant(instant));
        }
        else {
            throw new IllegalStateException(
                    "Neither PageBuilder#setTimestamp(Column, Instant) nor PageBuilder#setTimestamp(Column, Timestamp) found.");
        }
    }

    private static boolean hasExecGetPageBuilder()
    {
        try {
            Exec.class.getMethod("getPageBuilder", BufferAllocator.class, Schema.class, PageOutput.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    private static boolean hasExecGetPageReader()
    {
        try {
            Exec.class.getMethod("getPageReader", Schema.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    private static boolean hasGetTimestampColumn()
    {
        try {
            PageReader.class.getMethod("getTimestamp", Column.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    private static boolean hasGetTimestampInstantColumn()
    {
        try {
            PageReader.class.getMethod("getTimestampInstant", Column.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    @SuppressWarnings("deprecation")
    private static boolean hasSetTimestampTimestamp()
    {
        try {
            PageBuilder.class.getMethod("setTimestamp", Column.class, org.embulk.spi.time.Timestamp.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    private static boolean hasSetTimestampInstant()
    {
        try {
            PageBuilder.class.getMethod("setTimestamp", Column.class, Instant.class);
        }
        catch (final NoSuchMethodException ex) {
            return false;
        }
        return true;
    }

    private static final boolean HAS_EXEC_GET_PAGE_BUILDER = hasExecGetPageBuilder();
    private static final boolean HAS_EXEC_GET_PAGE_READER = hasExecGetPageReader();
    private static final boolean HAS_GET_TIMESTAMP_COLUMN = hasGetTimestampColumn();
    private static final boolean HAS_GET_TIMESTAMP_INSTANT_COLUMN = hasGetTimestampInstantColumn();
    private static final boolean HAS_SET_TIMESTAMP_INSTANT = hasSetTimestampInstant();
    private static final boolean HAS_SET_TIMESTAMP_TIMESTAMP = hasSetTimestampTimestamp();
}
