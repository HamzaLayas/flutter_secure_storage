package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class LegacyEncryptedPrefsMigrationTest {

    private static final String PREFS_NAME = "LegacyEncryptedPrefsMigrationTestData";
    private static final String KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";

    private Context context;
    private SharedPreferences dataPrefs;
    private NamespacedConfigSource configSource;
    private DeterministicAead keyDaead;
    private Aead valueAead;
    private SharedPreferences esp;

    /** Reversible stand-in for the current cipher, so tests can check what was written. */
    private static final FakeCipher FAKE_CIPHER = new FakeCipher();

    private static final class FakeCipher implements StorageCipher {
        @Override
        public byte[] encrypt(byte[] input) {
            return ("enc:" + new String(input, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public byte[] decrypt(byte[] input) {
            return new String(input, StandardCharsets.UTF_8).substring(4).getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public void deleteKey(Context context) {}
    }

    @Before
    public void setUp() throws Exception {
        context = RuntimeEnvironment.getApplication();
        dataPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        dataPrefs.edit().clear().commit();
        configSource = new NamespacedConfigSource(context, PREFS_NAME);
        configSource.edit().clear().commit();

        DeterministicAeadConfig.register();
        AeadConfig.register();
        keyDaead = KeysetHandle.generateNew(KeyTemplates.get("AES256_SIV"))
                .getPrimitive(RegistryConfiguration.get(), DeterministicAead.class);
        valueAead = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"))
                .getPrimitive(RegistryConfiguration.get(), Aead.class);
        esp = EncryptedSharedPreferences.forTest(PREFS_NAME, dataPrefs, valueAead, keyDaead);
    }

    /** Writes like v9 with encryptedSharedPreferences: true, plus the keyset entries ESP keeps. */
    private void writeV9(String key, String value) {
        esp.edit().putString(KEY_PREFIX + "_" + key, value).commit();
        dataPrefs.edit()
                .putString(LegacyEncryptedPrefsMigration.KEY_KEYSET_ALIAS, "keyset")
                .putString(LegacyEncryptedPrefsMigration.VALUE_KEYSET_ALIAS, "keyset")
                .commit();
    }

    /** Writes like v11 with the current cipher. */
    private void writeCurrent(String key, String value) {
        byte[] encrypted = FAKE_CIPHER.encrypt(value.getBytes(StandardCharsets.UTF_8));
        dataPrefs.edit().putString(KEY_PREFIX + "_" + key, Base64.encodeToString(encrypted, 0)).commit();
    }

    private String readCurrent(String key) {
        String raw = dataPrefs.getString(KEY_PREFIX + "_" + key, null);
        if (raw == null) {
            return null;
        }
        return new String(FAKE_CIPHER.decrypt(Base64.decode(raw, 0)), StandardCharsets.UTF_8);
    }

    private Map<String, LegacyEncryptedPrefsMigration.LegacyEntry> readLegacy() {
        return LegacyEncryptedPrefsMigration.readLegacyEntries(dataPrefs, PREFS_NAME, KEY_PREFIX, keyDaead, valueAead);
    }

    private int espEntryCount() {
        int count = 0;
        for (String key : dataPrefs.getAll().keySet()) {
            if (!key.contains(KEY_PREFIX)) {
                count++;
            }
        }
        return count;
    }

    @Test
    public void readLegacyEntries_decryptsV9Entries() {
        writeV9("appId", "35053");
        writeV9("deviceId", "d1d2");

        Map<String, LegacyEncryptedPrefsMigration.LegacyEntry> legacy = readLegacy();

        assertEquals(2, legacy.size());
        assertEquals("35053", legacy.get(KEY_PREFIX + "_appId").value);
        assertEquals("d1d2", legacy.get(KEY_PREFIX + "_deviceId").value);
    }

    @Test
    public void readLegacyEntries_skipsCurrentFormatAndForeignEntries() {
        // After a v9 -> v11 upgrade the same file holds both formats; ESP's own getAll()
        // throws on this file.
        writeV9("appId", "35053");
        writeCurrent("token", "jwt");
        dataPrefs.edit().putString("not-base64-and-not-esp", "x").putBoolean("flag", true).commit();

        Map<String, LegacyEncryptedPrefsMigration.LegacyEntry> legacy = readLegacy();

        assertEquals(1, legacy.size());
        assertEquals("35053", legacy.get(KEY_PREFIX + "_appId").value);
    }

    @Test
    public void readLegacyEntries_skipsKeysWithoutPrefix() {
        esp.edit().putString("someOtherLibraryKey", "v").commit();
        writeV9("appId", "35053");

        assertEquals(1, readLegacy().size());
    }

    @Test
    public void readLegacyEntries_keysetFromAnotherFileNameDoesNotDecrypt() {
        writeV9("appId", "35053");

        Map<String, LegacyEncryptedPrefsMigration.LegacyEntry> legacy =
                LegacyEncryptedPrefsMigration.readLegacyEntries(dataPrefs, "OtherFile", KEY_PREFIX, keyDaead, valueAead);

        assertTrue(legacy.isEmpty());
    }

    @Test
    public void migrate_copiesMissingKeysAndKeepsNewerCurrentValues() throws Exception {
        writeV9("appId", "35053");
        writeV9("deviceId", "old-device");
        writeCurrent("deviceId", "new-device");

        LegacyEncryptedPrefsMigration.Result result =
                LegacyEncryptedPrefsMigration.migrate(dataPrefs, configSource, readLegacy(), FAKE_CIPHER);

        assertEquals(1, result.migrated);
        assertEquals(1, result.keptCurrent);
        assertEquals("35053", readCurrent("appId"));
        assertEquals("new-device", readCurrent("deviceId"));
    }

    @Test
    public void migrate_removesLegacyEntriesAndKeysetsAndSetsFlag() throws Exception {
        writeV9("appId", "35053");
        writeCurrent("token", "jwt");

        LegacyEncryptedPrefsMigration.migrate(dataPrefs, configSource, readLegacy(), FAKE_CIPHER);

        assertEquals(0, espEntryCount());
        assertFalse(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertTrue(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
        assertEquals("jwt", readCurrent("token"));
    }

    @Test
    public void migrate_rerunAfterCrashBeforeCleanupKeepsCopiedValues() throws Exception {
        writeV9("appId", "35053");
        // Simulate a crash after the copy commit: the value is already in current storage,
        // the ESP entries and flag are not cleaned up yet.
        writeCurrent("appId", "35053");

        LegacyEncryptedPrefsMigration.Result result =
                LegacyEncryptedPrefsMigration.migrate(dataPrefs, configSource, readLegacy(), FAKE_CIPHER);

        assertEquals(0, result.migrated);
        assertEquals(1, result.keptCurrent);
        assertEquals("35053", readCurrent("appId"));
        assertEquals(0, espEntryCount());
    }

    @Test
    public void migrate_deletedAfterMigrationStaysDeleted() throws Exception {
        writeV9("appId", "35053");
        LegacyEncryptedPrefsMigration.migrate(dataPrefs, configSource, readLegacy(), FAKE_CIPHER);

        // deleteAll() only clears prefixed keys; nothing legacy may be left to resurface.
        dataPrefs.edit().remove(KEY_PREFIX + "_appId").commit();

        assertTrue(readLegacy().isEmpty());
        assertNull(readCurrent("appId"));
    }

    @Test
    public void migrateIfNeeded_doesNothingWhenFlagIsSet() {
        writeV9("appId", "35053");
        configSource.edit().putBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, true).commit();

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config(), dataPrefs, configSource, FAKE_CIPHER);

        assertTrue(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertNull(readCurrent("appId"));
    }

    @Test
    public void migrateIfNeeded_flagsInstallWithoutKeysets() {
        writeCurrent("token", "jwt");

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config(), dataPrefs, configSource, FAKE_CIPHER);

        assertTrue(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
        assertEquals("jwt", readCurrent("token"));
    }

    @Test
    public void migrateIfNeeded_leavesDataWhenNoCipherYet() {
        writeV9("appId", "35053");

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config(), dataPrefs, configSource, null);

        assertTrue(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertFalse(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
    }

    @Test
    public void migrateIfNeeded_leavesDataWhenMasterKeyIsMissing() {
        // Robolectric has no AndroidKeyStore, which is the same as a missing master key.
        writeV9("appId", "35053");

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config(), dataPrefs, configSource, FAKE_CIPHER);

        assertTrue(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertFalse(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
        assertNull(readCurrent("appId"));
    }

    @Test
    public void migrateIfNeeded_emptyStoreOnlyLeavesLegacyDataWhenStoreIsInUse() {
        writeV9("fingerPrintPassword", "old-password");
        writeCurrent("appId", "40001");

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config(), dataPrefs, configSource, FAKE_CIPHER);

        assertTrue(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertFalse(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
        assertNull(readCurrent("fingerPrintPassword"));
        assertEquals(1, readLegacy().size());
    }

    @Test
    public void migrateIfNeeded_offDoesNothing() {
        writeV9("appId", "35053");

        LegacyEncryptedPrefsMigration.migrateIfNeeded(context, config("off"), dataPrefs, configSource, FAKE_CIPHER);

        assertTrue(LegacyEncryptedPrefsMigration.hasKeysets(dataPrefs));
        assertFalse(configSource.getBoolean(LegacyEncryptedPrefsMigration.MIGRATED_FLAG, false));
    }

    @Test
    public void config_defaultsToEmptyStoreOnly() {
        assertEquals(FlutterSecureStorageConfig.LEGACY_ESP_RECOVERY_EMPTY_STORE_ONLY,
                config().getLegacyEncryptedPrefsRecovery());
        assertEquals(FlutterSecureStorageConfig.LEGACY_ESP_RECOVERY_FILL_MISSING,
                config("fillMissing").getLegacyEncryptedPrefsRecovery());
    }

    @Test
    public void decodeString_handlesNonStringNullMarkerAndTruncatedValues() {
        assertEquals("abc", LegacyEncryptedPrefsMigration.decodeString(encoded(0, "abc")));
        assertNull(LegacyEncryptedPrefsMigration.decodeString(encoded(0, "__NULL__")));
        assertNull(LegacyEncryptedPrefsMigration.decodeString(encoded(2, "abc")));
        assertNull(LegacyEncryptedPrefsMigration.decodeString(new byte[] {0, 0, 0, 0, 0, 0, 0, 9}));
        assertNull(LegacyEncryptedPrefsMigration.decodeString(new byte[] {0, 0}));
    }

    private static byte[] encoded(int type, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(8 + bytes.length).putInt(type).putInt(bytes.length).put(bytes).array();
    }

    private FlutterSecureStorageConfig config() {
        return config(null);
    }

    private FlutterSecureStorageConfig config(String recoveryMode) {
        Map<String, Object> options = new HashMap<>();
        options.put("sharedPreferencesName", PREFS_NAME);
        if (recoveryMode != null) {
            options.put("legacyEncryptedPrefsRecovery", recoveryMode);
        }
        return new FlutterSecureStorageConfig(options);
    }
}
