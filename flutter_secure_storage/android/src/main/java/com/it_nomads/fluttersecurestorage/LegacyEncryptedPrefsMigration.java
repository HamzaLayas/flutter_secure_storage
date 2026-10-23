package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.integration.android.AndroidKeysetManager;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Moves data written by v9 with {@code encryptedSharedPreferences: true} into the current
 * cipher storage.
 * <p>
 * v11 removed the EncryptedSharedPreferences (ESP) backend and expects v10 to have migrated
 * it, but v10.3.2+ can skip that migration (#1293) and an app may go straight from v9 to v11.
 * In both cases the ESP data is still in the data prefs file, under encrypted key names that
 * the key-prefix filter never matches, so reads return null.
 * <p>
 * Like the darwin cross-accessibility fallback (#1269), this only fills gaps: a key that
 * already exists in current storage was written after the upgrade and wins over the legacy
 * value. By default ({@code emptyStoreOnly}) it only runs while current storage is empty,
 * since gap-filling a store the app already uses can bring back keys it has deleted;
 * {@code fillMissing} opts into that. The legacy entries are removed once copied, so a later
 * deleteAll() can't bring them back.
 * <p>
 * The ESP format is read with Tink directly, one entry at a time, instead of through
 * EncryptedSharedPreferences: its getAll() throws on the first key name it can't decrypt,
 * and after a v11 upgrade the same file also holds current-format entries.
 */
final class LegacyEncryptedPrefsMigration {

    private static final String TAG = "FlutterSecureStorage";

    // Written by v10 after its own ESP migration; reused so v10-migrated installs are skipped.
    static final String MIGRATED_FLAG = "ENCRYPTED_PREFERENCES_MIGRATED";

    static final String KEY_KEYSET_ALIAS = "__androidx_security_crypto_encrypted_prefs_key_keyset__";
    static final String VALUE_KEYSET_ALIAS = "__androidx_security_crypto_encrypted_prefs_value_keyset__";
    static final String MASTER_KEY_ALIAS = "_androidx_security_master_key_";
    private static final String MASTER_KEY_URI = "android-keystore://" + MASTER_KEY_ALIAS;

    // androidx.security.crypto.EncryptedSharedPreferences value encoding.
    private static final int TYPE_STRING = 0;
    private static final String NULL_VALUE = "__NULL__";

    private LegacyEncryptedPrefsMigration() {}

    /** One ESP entry: its stored (encrypted) pref key and its decrypted string value. */
    static final class LegacyEntry {
        final String storedKey;
        final String value;

        LegacyEntry(String storedKey, String value) {
            this.storedKey = storedKey;
            this.value = value;
        }
    }

    /** What a migration run did, for logging and tests. */
    static final class Result {
        final int migrated;
        final int keptCurrent;

        Result(int migrated, int keptCurrent) {
            this.migrated = migrated;
            this.keptCurrent = keptCurrent;
        }
    }

    /**
     * Runs the migration if it's needed. Never throws: a failure is logged and leaves the
     * legacy data in place, so the next initialize() retries.
     */
    static void migrateIfNeeded(@NonNull Context context,
                                @NonNull FlutterSecureStorageConfig config,
                                @NonNull SharedPreferences dataPrefs,
                                @NonNull NamespacedConfigSource configSource,
                                @Nullable StorageCipher cipher) {
        String mode = config.getLegacyEncryptedPrefsRecovery();
        if (FlutterSecureStorageConfig.LEGACY_ESP_RECOVERY_OFF.equals(mode)
                || configSource.getBoolean(MIGRATED_FLAG, false)) {
            return;
        }
        if (!hasKeysets(dataPrefs)) {
            markMigrated(configSource);
            return;
        }
        if (FlutterSecureStorageConfig.LEGACY_ESP_RECOVERY_EMPTY_STORE_ONLY.equals(mode)
                && hasCurrentEntries(dataPrefs, config.getSharedPreferencesKeyPrefix())) {
            // The app already ran on current storage after the upgrade. Filling gaps could
            // bring back keys it deleted since (logout, disabled biometrics), so the legacy
            // data is left untouched unless the app opts into fillMissing.
            Log.i(TAG, "Legacy EncryptedSharedPreferences data left in place: current storage is not empty");
            return;
        }
        if (cipher == null) {
            // Per-operation biometric store: no cipher until the next prompt. v9 never wrote
            // ESP data behind biometrics, so this is not expected; leave it for a later run.
            Log.w(TAG, "Legacy EncryptedSharedPreferences data found, but no storage cipher is available yet");
            return;
        }
        if (!masterKeyExists()) {
            // Without the Keystore key the keysets can't be decrypted. Leave everything in
            // place so checkUpgradeStatus() keeps reporting it.
            Log.e(TAG, "Legacy EncryptedSharedPreferences data found, but its master key is missing");
            return;
        }

        try {
            String fileName = config.getEffectiveDataPrefsName();
            Map<String, LegacyEntry> legacy = readLegacyEntries(dataPrefs, fileName,
                    config.getSharedPreferencesKeyPrefix(), openKeyDaead(context, fileName),
                    openValueAead(context, fileName));
            Result result = migrate(dataPrefs, configSource, legacy, cipher);
            Log.i(TAG, "Migrated " + result.migrated + " items from legacy EncryptedSharedPreferences ("
                    + result.keptCurrent + " already had newer values)");
        } catch (Exception e) {
            Log.e(TAG, "Legacy EncryptedSharedPreferences migration failed; will retry on next start", e);
        }
    }

    /** Whether the data prefs still hold the ESP keysets. */
    static boolean hasKeysets(@NonNull SharedPreferences dataPrefs) {
        return dataPrefs.contains(KEY_KEYSET_ALIAS) || dataPrefs.contains(VALUE_KEYSET_ALIAS);
    }

    /** Whether current storage already holds data under {@code keyPrefix}. */
    static boolean hasCurrentEntries(@NonNull SharedPreferences dataPrefs, @NonNull String keyPrefix) {
        for (String key : dataPrefs.getAll().keySet()) {
            if (key.contains(keyPrefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decrypts every ESP string entry whose plain key contains {@code keyPrefix}, keyed by
     * that plain key. Entries that aren't ESP-encoded (current-format data, markers) are
     * skipped rather than failing the whole read.
     */
    @NonNull
    static Map<String, LegacyEntry> readLegacyEntries(@NonNull SharedPreferences dataPrefs,
                                                      @NonNull String fileName,
                                                      @NonNull String keyPrefix,
                                                      @NonNull DeterministicAead keyDaead,
                                                      @NonNull Aead valueAead) {
        Map<String, LegacyEntry> entries = new HashMap<>();
        byte[] keyAssociatedData = fileName.getBytes(StandardCharsets.UTF_8);

        for (Map.Entry<String, ?> entry : dataPrefs.getAll().entrySet()) {
            String storedKey = entry.getKey();
            if (!(entry.getValue() instanceof String)
                    || KEY_KEYSET_ALIAS.equals(storedKey)
                    || VALUE_KEYSET_ALIAS.equals(storedKey)
                    || storedKey.contains(keyPrefix)) {
                continue;
            }

            String plainKey;
            byte[] plainValue;
            try {
                plainKey = new String(keyDaead.decryptDeterministically(
                        Base64.decode(storedKey, Base64.DEFAULT), keyAssociatedData), StandardCharsets.UTF_8);
                plainValue = valueAead.decrypt(
                        Base64.decode((String) entry.getValue(), Base64.DEFAULT),
                        storedKey.getBytes(StandardCharsets.UTF_8));
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                continue; // not an ESP entry
            }

            if (!plainKey.contains(keyPrefix)) {
                continue;
            }
            String value = decodeString(plainValue);
            if (value != null) {
                entries.put(plainKey, new LegacyEntry(storedKey, value));
            }
        }
        return entries;
    }

    /**
     * Copies {@code legacy} into current storage, skipping keys that already exist there,
     * then removes the ESP entries and keysets and sets {@link #MIGRATED_FLAG}. Each step is
     * committed before the next, so a crash at any point is safe to rerun.
     */
    @NonNull
    static Result migrate(@NonNull SharedPreferences dataPrefs,
                          @NonNull NamespacedConfigSource configSource,
                          @NonNull Map<String, LegacyEntry> legacy,
                          @NonNull StorageCipher cipher) throws Exception {
        int migrated = 0;
        int keptCurrent = 0;
        List<String> legacyKeys = new ArrayList<>();

        SharedPreferences.Editor copy = dataPrefs.edit();
        for (Map.Entry<String, LegacyEntry> entry : legacy.entrySet()) {
            legacyKeys.add(entry.getValue().storedKey);
            if (dataPrefs.contains(entry.getKey())) {
                keptCurrent++;
                continue;
            }
            byte[] encrypted = cipher.encrypt(entry.getValue().value.getBytes(StandardCharsets.UTF_8));
            copy.putString(entry.getKey(), Base64.encodeToString(encrypted, 0));
            migrated++;
        }
        if (!copy.commit()) {
            throw new Exception("Failed to write migrated legacy entries");
        }

        SharedPreferences.Editor cleanup = dataPrefs.edit();
        for (String storedKey : legacyKeys) {
            cleanup.remove(storedKey);
        }
        cleanup.remove(KEY_KEYSET_ALIAS);
        cleanup.remove(VALUE_KEYSET_ALIAS);
        if (!cleanup.commit()) {
            throw new Exception("Failed to remove legacy entries after migration");
        }

        markMigrated(configSource);
        return new Result(migrated, keptCurrent);
    }

    private static void markMigrated(NamespacedConfigSource configSource) {
        configSource.edit().putBoolean(MIGRATED_FLAG, true).commit();
    }

    /** Decodes an ESP STRING value, or returns null for other types and the null marker. */
    @Nullable
    static String decodeString(@NonNull byte[] plainValue) {
        ByteBuffer buffer = ByteBuffer.wrap(plainValue);
        if (buffer.remaining() < 8 || buffer.getInt() != TYPE_STRING) {
            return null;
        }
        int length = buffer.getInt();
        if (length < 0 || length > buffer.remaining()) {
            return null;
        }
        String value = new String(plainValue, buffer.position(), length, StandardCharsets.UTF_8);
        return NULL_VALUE.equals(value) ? null : value;
    }

    private static boolean masterKeyExists() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            return keyStore.containsAlias(MASTER_KEY_ALIAS);
        } catch (Exception e) {
            Log.w(TAG, "Could not check for the legacy master key", e);
            return false;
        }
    }

    // No key template on purpose: with a template, a missing keyset would be generated and
    // written over the data. hasKeysets() is checked first, so build() only reads.
    private static DeterministicAead openKeyDaead(Context context, String fileName) throws Exception {
        DeterministicAeadConfig.register();
        KeysetHandle handle = new AndroidKeysetManager.Builder()
                .withSharedPref(context, KEY_KEYSET_ALIAS, fileName)
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .getKeysetHandle();
        return handle.getPrimitive(RegistryConfiguration.get(), DeterministicAead.class);
    }

    private static Aead openValueAead(Context context, String fileName) throws Exception {
        AeadConfig.register();
        KeysetHandle handle = new AndroidKeysetManager.Builder()
                .withSharedPref(context, VALUE_KEYSET_ALIAS, fileName)
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .getKeysetHandle();
        return handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    }
}
