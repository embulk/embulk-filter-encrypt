/*
 * Copyright 2016 The Embulk project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.embulk.filter.encrypt;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Region;
import com.google.common.collect.ImmutableList;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.TaskSource;
import org.embulk.filter.encrypt.EncryptFilterPlugin.PluginTask;
import org.embulk.spi.Column;
import org.embulk.spi.ColumnVisitor;
import org.embulk.spi.FilterPlugin;
import org.embulk.spi.PageOutput;
import org.embulk.spi.PageReader;
import org.embulk.spi.Schema;
import org.embulk.spi.TestPageBuilderReader.MockPageOutput;
import org.embulk.spi.type.Types;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class TestEncryptFilterPlugin
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private EncryptFilterPlugin plugin;

    private ConfigSource defaultConfig()
    {
        return runtime.getExec().newConfigSource()
                .set("type", "encrypt")
                .set("algorithm", "AES-256-CBC")
                .set("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42")
                .set("iv_hex", "2A1D6BD59D2DB50A59364BAD3B9B6544");
    }

    private ConfigSource s3Config()
    {
        ConfigSource awsParams = runtime.getExec().newConfigSource()
                .set("region", "us-east-2")
                .set("access_key", "a_access_key")
                .set("secret_key", "a_secret_key")
                .set("bucket", "a_bucket")
                .set("path", "a_path");

        return runtime.getExec().newConfigSource()
                .set("type", "encrypt")
                .set("algorithm", "AES-256-CBC")
                .set("key_type", "s3")
                .setNested("aws_params", awsParams);
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
                .remove("iv_hex")
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
                .remove("iv_hex")
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
                .remove("iv_hex")
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

        final PluginTask task = EncryptFilterPlugin.CONFIG_MAPPER.map(config, PluginTask.class);

        assertEquals(
                plaintext,
                decrypt(ciphertext,
                        task.getAlgorithm(),
                        task.getKeyHex().get(),
                        task.getIvHex().orElse(null),
                        BASE64));
        try {
            decrypt(ciphertext,
                    task.getAlgorithm(),
                    task.getKeyHex().get(),
                    task.getIvHex().orElse(null),
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

        final PluginTask task = EncryptFilterPlugin.CONFIG_MAPPER.map(config, PluginTask.class);

        assertEquals(
                plaintext,
                decrypt(ciphertext,
                        task.getAlgorithm(),
                        task.getKeyHex().get(),
                        task.getIvHex().orElse(null),
                        HEX));
        try {
            decrypt(ciphertext,
                    task.getAlgorithm(),
                    task.getKeyHex().get(),
                    task.getIvHex().orElse(null),
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
        final PluginTask task = EncryptFilterPlugin.CONFIG_MAPPER.map(config, PluginTask.class);
        assertEquals(task.getOutputEncoding(), BASE64);
    }

    @Test
    // Previously, missing key_hex does throw a ConfigException but doesn't pinpoint the problematic field
    public void absence_of_encryption_key_should_yell_a_meaningful_ConfigException() throws Exception
    {
        ConfigSource config = defaultConfig()
                .remove("key_hex")
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("key_hex");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_iv_on_a_required_iv_algorithm_should_yell_a_meaningful_ConfigException() throws Exception
    {
        ConfigSource config = defaultConfig()
                .remove("iv_hex")
                .set("algorithm", "AES-256-CBC")
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("iv_hex");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    // Previously, this will throw
    public void presence_of_iv_on_a_non_iv_algorithm_should_be_silent() throws Exception
    {
        ConfigSource config = defaultConfig()
                .remove("iv_hex")
                .set("algorithm", "AES-128-ECB")
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test()
    public void encrypt_with_required_IV_algorithm_for_s3() throws Exception
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("should_be_encrypted"));
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42");
        keys.put("iv_hex", "2A1D6BD59D2DB50A59364BAD3B9B6544");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        List rawRecord = ImmutableList.of("My super secret");
        List filteredRecord = applyFilter(config, schema, rawRecord);

        String plaintext = (String) rawRecord.get(0);
        String ciphertext = (String) filteredRecord.get(0);

        assertNotEquals(plaintext, ciphertext);
        config.set("key_hex", keys.get("key_hex"));
        config.set("iv_hex", keys.get("iv_hex"));
        assertEquals(plaintext, decrypt(ciphertext, AES_256_CBC, config));
    }

    @Test()
    public void encrypt_with_not_required_IV_algorithm_for_s3() throws Exception
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("should_be_encrypted"))
                .set("algorithm", "AES-256-ECB");
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42");
        keys.put("iv_hex", "2A1D6BD59D2DB50A59364BAD3B9B6544");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        List rawRecord = ImmutableList.of("My super secret");
        List filteredRecord = applyFilter(config, schema, rawRecord);

        String plaintext = (String) rawRecord.get(0);
        String ciphertext = (String) filteredRecord.get(0);

        assertNotEquals(plaintext, ciphertext);
        config.set("key_hex", keys.get("key_hex"));
        assertEquals(plaintext, decrypt(ciphertext, AES_256_ECB, config));
    }

    @Test()
    public void encrypt_with_not_required_IV_algorithm_for_s3_should_ignore_IV() throws Exception
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("should_be_encrypted"))
                .set("algorithm", "AES-256-ECB");
        Schema schema = Schema.builder()
                .add("should_be_encrypted", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        List rawRecord = ImmutableList.of("My super secret");
        List filteredRecord = applyFilter(config, schema, rawRecord);

        String plaintext = (String) rawRecord.get(0);
        String ciphertext = (String) filteredRecord.get(0);

        assertNotEquals(plaintext, ciphertext);
        config.set("key_hex", keys.get("key_hex"));
        assertEquals(plaintext, decrypt(ciphertext, AES_256_ECB, config));
    }

    @Test
    public void absence_of_aws_params_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"))
                .remove("aws_params");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("AWS Params");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_aws_region_param_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        config.getNested("aws_params")
            .remove("region");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("region");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_aws_path_param_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        config.getNested("aws_params")
                .remove("path");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("path");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_aws_bucket_param_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        config.getNested("aws_params")
                .remove("bucket");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("bucket");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_aws_access_key_param_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        config.getNested("aws_params")
                .remove("access_key");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("access_key");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_aws_secret_key_param_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        config.getNested("aws_params")
                .remove("secret_key");
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();
        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("secret_key");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_encryption_key_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("key_hex");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void absence_of_iv_on_a_required_iv_algorithm_for_s3_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource config = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("iv_hex");
        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    // Previously, this will throw
    public void presence_of_iv_on_a_non_iv_algorithm_for_s3_should_be_silent()
    {
        ConfigSource config = s3Config()
                .set("algorithm", "AES-128-ECB")
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        Schema schema = Schema.builder()
                .add("attempt_to_encrypt", Types.STRING)
                .build();

        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "D0867C9310D061F17ACD11EB30DE68265DCB79849BE5FB2BE157919D19BF2F42");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class));

        applyFilter(config, schema, ImmutableList.of("Try to encrypt me buddy!"));
    }

    @Test
    public void s3_client_should_reflect_region_config()
    {
        ConfigSource configSource = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));

        final AmazonS3 s3Client = plugin.newS3Client(
                EncryptFilterPlugin.CONFIG_MAPPER.map(configSource, EncryptFilterPlugin.PluginTask.class).getAWSParams().get());

        assertEquals(s3Client.getRegion(), Region.US_East_2);
    }

    @Test
    public void s3_client_invalid_region_should_yell_a_meaningful_ConfigException()
    {
        ConfigSource configSource = s3Config()
                .set("column_names", ImmutableList.of("attempt_to_encrypt"));
        configSource.getNested("aws_params")
                .set("region", "invalid_region");

        expectedException.expect(ConfigException.class);
        expectedException.expectMessage("Unable to find a region via the region provider chain");
        plugin.newS3Client(
                EncryptFilterPlugin.CONFIG_MAPPER.map(configSource, EncryptFilterPlugin.PluginTask.class).getAWSParams().get());
    }

    /** Apply the filter to a single record */
    private PageReader applyFilter(ConfigSource config, final Schema schema, final Object... rawRecord)
    {
        if (rawRecord.length > schema.getColumnCount()) {
            throw new UnsupportedOperationException("applyFilter() only supports a single record, " +
                    "number of supplied values exceed the schema column size.");
        }

        final MockPageOutput filteredOutput = new MockPageOutput();

        plugin.transaction(config, schema, new FilterPlugin.Control()
        {
            @Override
            public void run(TaskSource taskSource, Schema outputSchema)
            {
                PageOutput originalOutput = plugin.open(taskSource, schema, outputSchema, filteredOutput);
                originalOutput.add(buildPage(runtime.getBufferAllocator(), schema, rawRecord).get(0));
                originalOutput.finish();
                originalOutput.close();
            }
        });
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
        final PluginTask task = EncryptFilterPlugin.CONFIG_MAPPER.map(config, PluginTask.class);
        return decrypt(
                ciphertext,
                task.getAlgorithm(),
                task.getKeyHex().get(),
                task.getIvHex().orElse(null),
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
        final PluginTask task = EncryptFilterPlugin.CONFIG_MAPPER.map(config, PluginTask.class);
        return decrypt(
                ciphertext,
                algo,
                task.getKeyHex().get(),
                task.getIvHex().orElse(null),
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
