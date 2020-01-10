package ch.papers.securestorage

import android.os.Build
import android.security.keystore.UserNotAuthenticatedException
import java.io.*
import java.nio.charset.Charset
import java.security.Key
import java.security.MessageDigest
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

/**
 * Created by Dominik on 19.01.2018.
 */
class SecureFileStorage(private val masterSecret: Key?, private val salt: ByteArray, private val baseDir: File) {

    fun read(fileKey: String, secret: ByteArray = "".toByteArray(), success: (String) -> Unit, error: (Exception) -> Unit, requestAuthentication: (() -> Unit) -> Unit) {
        thread {
            try {
                val fileInputStream = FileInputStream(fileForHashedKey(hashForKey(fileKey)))

                val fsCipherInputStream = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    val fsCipher =
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                val iv = ByteArray(16)
                                fileInputStream.read(iv)

                                val fsCipher = Cipher.getInstance(Constants.FILESYSTEM_CIPHER_ALGORITHM)
                                fsCipher.init(Cipher.DECRYPT_MODE, masterSecret, IvParameterSpec(iv))
                                fsCipher
                            } else {
                                val fsCipher = Cipher.getInstance(Constants.FILESYSTEM_FALLBACK_CIPHER_ALGORITHM)
                                fsCipher.init(Cipher.DECRYPT_MODE, masterSecret)
                                fsCipher
                            }

                    CipherInputStream(fileInputStream, fsCipher)
                } else {
                    fileInputStream
                }

                val encryptionSecret = encryptionSecret(secret, hashForKey(fileKey))

                val specificSecretKey = SecretKeySpec(encryptionSecret, 0, encryptionSecret.size, "AES")
                val specificSecretCipher = Cipher.getInstance(Constants.FILESYSTEM_CIPHER_ALGORITHM)

                specificSecretCipher.init(Cipher.DECRYPT_MODE, specificSecretKey, IvParameterSpec(ivForKey(fileKey)))

                val secretCipherInputStream = CipherInputStream(fsCipherInputStream, specificSecretCipher)

                val fileValue = secretCipherInputStream.readTextAndClose()
                success(fileValue)
            } catch (e: IOException) {
                if (e.isSecurityError) {
                    error(Exception("Wrong master key, could not decrypt the data."))
                } else {
                    error(e)
                }
            } catch (e: Exception) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (e is UserNotAuthenticatedException) {
                        requestAuthentication { read(fileKey, secret, success, error, requestAuthentication) }
                    } else {
                        error(e)
                    }
                } else {
                    error(e)
                }
            }
        }
    }

    fun write(fileKey: String, fileData: String, secret: ByteArray = "".toByteArray(), success: () -> Unit, error: (Exception) -> Unit, requestAuthentication: (() -> Unit) -> Unit) {
        thread {
            try {
                val file = fileForHashedKey(hashForKey(fileKey))

                if (!file.exists()) {
                    file.createNewFile()
                }

                val fileOutputStream = FileOutputStream(file)

                val fsCipherOutputStream = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                    val fsCipher =
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                Cipher.getInstance(Constants.FILESYSTEM_CIPHER_ALGORITHM)
                            } else {
                                Cipher.getInstance(Constants.FILESYSTEM_FALLBACK_CIPHER_ALGORITHM)
                            }
                    fsCipher.init(Cipher.ENCRYPT_MODE, masterSecret)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        fileOutputStream.write(fsCipher.iv)
                    }
                    CipherOutputStream(fileOutputStream, fsCipher)
                } else {
                    fileOutputStream
                }

                val encryptionSecret = encryptionSecret(secret, hashForKey(fileKey))

                val specificSecretKey = SecretKeySpec(encryptionSecret, 0, encryptionSecret.size, "AES")
                val specificSecretCipher = Cipher.getInstance(Constants.FILESYSTEM_CIPHER_ALGORITHM)

                specificSecretCipher.init(Cipher.ENCRYPT_MODE, specificSecretKey, IvParameterSpec(ivForKey(fileKey)))

                CipherOutputStream(fsCipherOutputStream, specificSecretCipher).use {
                    it.write(fileData.toByteArray())
                    it.flush()
                }

                success()
            } catch (e: IOException) {
                if (e.isSecurityError) {
                    error(Exception("Wrong master key, could not encrypt the data."))
                } else {
                    error(e)
                }
            } catch (e: Exception) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (e is UserNotAuthenticatedException) {
                        requestAuthentication { write(fileKey, fileData, secret, success, error, requestAuthentication) }
                    } else {
                        error(e)
                    }
                } else {
                    error(e)
                }
            }
        }
    }

    fun remove(fileKey: String, success: () -> Unit, error: (error: Exception) -> Unit) {
        thread {
            try {
                val file = fileForHashedKey(hashForKey(fileKey))
                val result = file.delete()
                if (result) {
                    success()
                } else {
                    throw Exception("could not delete file")
                }
            } catch (e: Exception) {
                error(e)
            }
        }
    }

    private fun encryptionSecret(secret: ByteArray, key: ByteArray): ByteArray {
        return MessageDigest.getInstance(Constants.DIGEST_ALGORITHM).digest(secret + key)
    }

    private fun ivForKey(key: String): ByteArray {
        return hashForKey(key).sliceArray(IntRange(0, 15))
    }

    private fun hashForKey(key: String): ByteArray {
        return MessageDigest.getInstance(Constants.DIGEST_ALGORITHM).digest(salt + key.toByteArray())
    }

    private fun fileForHashedKey(hashedKey: ByteArray): File {
        return File(baseDir, hashedKey.toHexString())
    }

    private fun InputStream.readTextAndClose(charset: Charset = Charsets.UTF_8): String {
        return this.bufferedReader(charset).use { it.readText() }
    }

    private val IOException.isSecurityError: Boolean
        get() = cause is BadPaddingException
}