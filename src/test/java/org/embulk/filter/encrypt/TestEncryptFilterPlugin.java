package org.embulk.filter.encrypt;

import com.google.common.collect.ImmutableList;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigSource;
import org.embulk.filter.encrypt.EncryptFilterPlugin.PluginTask;
import org.embulk.spi.Column;
import org.embulk.spi.ColumnVisitor;
import org.embulk.spi.PageOutput;
import org.embulk.spi.PageReader;
import org.embulk.spi.Schema;
import org.embulk.spi.TestPageBuilderReader.MockPageOutput;
import org.embulk.spi.type.Types;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.io.BaseEncoding.base16;
import static com.google.common.io.BaseEncoding.base64;
import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNull;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_128_CBC;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_128_ECB;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_192_CBC;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_192_ECB;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_256_CBC;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Algorithm.AES_256_ECB;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Encoder;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Encoder.BASE64;
import static org.embulk.filter.encrypt.EncryptFilterPlugin.Encoder.HEX;
import static org.embulk.spi.PageTestUtils.buildPage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

public class TestEncryptFilterPlugin
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    private EncryptFilterPlugin plugin;

    private ConfigSource defaultConfig()
    {
        return runtime.getExec().newConfigSource()
                .set("type", "encrypt")
                .set("algorithm", "AES-256-CBC")
                .set("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42")
                .set("iv_hex", "2A1D6BD59D2DB50A59364BAD3B9B6544");
    }

    @Before
    public void setup()
    {
        plugin = new EncryptFilterPlugin();
    }

    @Test(expected = GeneralSecurityException.class)
    public void encrypt_with_AES_256_CBC() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-256-CBC")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        List rawRecord = ImmutableList.of("My super secret");
        List filteredRecord = applyFilter(config, schema, rawRecord);

        String plaintext = (String) rawRecord.get(0);
        String ciphertext = (String) filteredRecord.get(0);

        assertNotEquals(plaintext, ciphertext);
        assertEquals(plaintext, decrypt(ciphertext, AES_256_CBC, config));

        // Apparently it should fail when decrypt with a different algorithm
        decrypt(ciphertext, AES_128_ECB, config);
    }

    @Test
    public void encrypt_with_AES_256_CBC__alias_should_work_too() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_256_CBC,
                        config));
    }

    @Test
    public void encrypt_with_AES_192_CBC() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-192-CBC")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_192_CBC,
                        config));
    }

    @Test
    public void encrypt_with_AES_128_CBC() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-128-CBC")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_128_CBC,
                        config));
    }

    @Test
    public void encrypt_with_AES_256_ECB() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-256-ECB")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_256_ECB,
                        config));
    }

    @Test
    public void encrypt_with_AES_192_ECB() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-192-ECB")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_192_ECB,
                        config));
    }

    @Test
    public void encrypt_with_AES_128_ECB() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("algorithm", "AES-128-ECB")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "My super secret!";

        assertEquals(
                plaintext,
                decrypt((String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0),
                        AES_128_ECB,
                        config));
    }

    @Test
    public void encrypt_selective_columns() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .add("should_be_unencrypted", Types.STRING)
                .build();

        List raw = ImmutableList.of("My super secret!", "Hey yo!");
        List filtered = applyFilter(config, schema, raw);

        // Encrypted column
        assertNotEquals(raw.get(0), filtered.get(0));
        assertEquals(raw.get(0), decrypt((String) filtered.get(0), config));

        // Unencrypted column
        assertEquals(raw.get(1), filtered.get(1));
    }

    @Test
    public void nonstring_is_not_intact_whatsoever() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.LONG)
                .build();

        List raw = ImmutableList.of(1L);
        List filtered = applyFilter(config, schema, raw);

        assertEquals(raw, filtered);
    }

    @Test
    public void base64_encoding() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("output_encoding", "base64")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "a_plaintext";

        String ciphertext = (String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0);

        PluginTask task = config.loadConfig(PluginTask.class);

        assertEquals(
                plaintext,
                decrypt(ciphertext,
                        task.getAlgorithm(),
                        task.getKeyHex().orNull(),
                        task.getIvHex().orNull(),
                        BASE64));
        try {
            decrypt(ciphertext,
                    task.getAlgorithm(),
                    task.getKeyHex().orNull(),
                    task.getIvHex().orNull(),
                    HEX);
        }
        catch (IllegalArgumentException ex) {
            return;
        }
        fail("Expected an IllegalArgumentException for mismatch encoding!");
    }

    @Test
    public void hex_encoding() throws Exception
    {
        ConfigSource config = defaultConfig()
                .set("output_encoding", "hex")
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        String plaintext = "a_plaintext";

        String ciphertext = (String) applyFilter(config, schema, ImmutableList.of(plaintext)).get(0);

        PluginTask task = config.loadConfig(PluginTask.class);

        assertEquals(
                plaintext,
                decrypt(ciphertext,
                        task.getAlgorithm(),
                        task.getKeyHex().orNull(),
                        task.getIvHex().orNull(),
                        HEX));
        try {
            decrypt(ciphertext,
                    task.getAlgorithm(),
                    task.getKeyHex().orNull(),
                    task.getIvHex().orNull(),
                    BASE64);
        }
        // Since hex/base16 is a totally valid subset of base64, this won't yield
        // an IllegalArgumentException when encoding, but a decrypting exception instead.
        catch (GeneralSecurityException ex) {
            return;
        }
        fail("Expected an IllegalArgumentException for mismatch encoding!");
    }

    @Test
    public void default_output_encoding_should_be_base64()
    {
        ConfigSource config = defaultConfig()
                .remove("output_encoding")
                .set("column_names", emptyList());
        PluginTask task = config.loadConfig(PluginTask.class);
        assertEquals(task.getOutputEncoding(), BASE64);
    }

    /** Apply the filter to a single record */
    private PageReader applyFilter(ConfigSource config, Schema schema, Object... rawRecord)
    {
        if (rawRecord.length > schema.getColumnCount()) {
            throw new UnsupportedOperationException("applyFilter() only supports a single record, " +
                    "number of supplied values exceed the schema column size.");
        }
        PluginTask task = config.loadConfig(PluginTask.class);

        MockPageOutput filteredOutput = new MockPageOutput();

        PageOutput originalOutput = plugin.open(task.dump(), schema, schema, filteredOutput);
        originalOutput.add(buildPage(runtime.getBufferAllocator(), schema, rawRecord).get(0));
        originalOutput.finish();
        originalOutput.close();

        assert filteredOutput.pages.size() == 1;
        PageReader reader = new PageReader(schema);
        reader.setPage(filteredOutput.pages.get(0));
        reader.nextRecord();

        return reader;
    }

    /** Conveniently returning a List after apply a filter over the original list */
    private List applyFilter(ConfigSource config, Schema schema, List rawRecord)
    {
        try (PageReader reader = applyFilter(config, schema, rawRecord.toArray())) {
            return readToList(reader, schema);
        }
    }

    private static List readToList(final PageReader reader, Schema schema)
    {
        final Object[] filtered = new Object[schema.getColumnCount()];
        schema.visitColumns(new ColumnVisitor()
        {
            @Override
            public void booleanColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getBoolean(column);
            }

            @Override
            public void longColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getLong(column);
            }

            @Override
            public void doubleColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getDouble(column);
            }

            @Override
            public void stringColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getString(column);
            }

            @Override
            public void timestampColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getTimestamp(column);
            }

            @Override
            public void jsonColumn(Column column)
            {
                filtered[column.getIndex()] = reader.getJson(column);
            }
        });
        return Arrays.asList(filtered);
    }

    private static String decrypt(String ciphertext, Algorithm algo, String keyHex, String ivHex, Encoder encoder)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance(algo.getJavaName());
        SecretKeySpec key = new SecretKeySpec(base16().decode(keyHex), algo.getJavaKeySpecName());
        if (algo.useIv()) {
            requireNonNull(ivHex, format("IV is required for this algorithm (%s)", algo));
            IvParameterSpec iv = new IvParameterSpec(base16().decode(ivHex));
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        return new String(cipher.doFinal(decode(ciphertext, encoder)), UTF_8);
    }

    private static String decrypt(String ciphertext, ConfigSource config)
            throws NoSuchPaddingException,
            InvalidKeyException,
            NoSuchAlgorithmException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException
    {
        PluginTask task = config.loadConfig(PluginTask.class);
        return decrypt(
                ciphertext,
                task.getAlgorithm(),
                task.getKeyHex().orNull(),
                task.getIvHex().orNull(),
                task.getOutputEncoding());
    }

    /** Just to be explicit about the algorithm in used */
    private static String decrypt(String ciphertext, Algorithm algo, ConfigSource config)
            throws NoSuchPaddingException,
            InvalidKeyException,
            NoSuchAlgorithmException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException
    {
        PluginTask task = config.loadConfig(PluginTask.class);
        return decrypt(
                ciphertext,
                algo,
                task.getKeyHex().orNull(),
                task.getIvHex().orNull(),
                task.getOutputEncoding());
    }

    /** Decoding by reversing the originalEncoder */
    private static byte[] decode(String encoded, Encoder originalEncoder)
    {
        switch (originalEncoder) {
            case BASE64:
                return base64().decode(encoded);
            case HEX:
                return base16().decode(encoded);
            default:
                throw new UnsupportedOperationException("Unrecognized encoder: " + originalEncoder);
        }
    }
}
