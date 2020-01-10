package com.example.user.aesencryptor

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.view.Gravity
import android.view.WindowManager
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_main)
        System.gc()

        edittext_text.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable) {}
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
                if (s.isNotEmpty()) {
                    edittext_text.gravity = Gravity.START and Gravity.TOP
                } else {
                    edittext_text.gravity = Gravity.CENTER
                }
            }
        })

        button_encrypt.setOnClickListener() {
            val text: String = edittext_text.text.toString()
            val pass: String = edittext_password.text.toString()
            val toast: Toast
            if (text.isEmpty() or pass.isEmpty()) {
                toast = Toast.makeText(this, "Text fields cannot be empty", Toast.LENGTH_SHORT)
                toast.setGravity(Gravity.BOTTOM, 0, 150)
                toast.show()
            } else {
                edittext_text.setText(encryptAES(text, pass))
            }
        }

        System.gc()
        System.gc()

        button_decrypt.setOnClickListener {
            val text: String = edittext_text.text.toString()
            val pass: String = edittext_password.text.toString()
            var toast: Toast = Toast.makeText(this, "placeholder", Toast.LENGTH_SHORT)
            if (text.isEmpty() or pass.isEmpty()) {
                toast = Toast.makeText(this, "Text fields cannot be empty", Toast.LENGTH_SHORT)
                toast.setGravity(Gravity.BOTTOM, 0, 150)
                toast.show()
            } else {
                edittext_text.setText(decryptAES(text, pass, toast))
            }
        }

        System.gc()
    }

    override fun onDestroy() {
        super.onDestroy()

        System.gc()
        System.gc()
        Runtime.getRuntime().gc()
    }

    private fun getSaltLength(): Int {
        return 32
    }

    private fun getRandomBytes(): ByteArray {
        val ba = ByteArray(getSaltLength())
        SecureRandom().nextBytes(ba)
        return ba
    }

    private fun encryptAES(plainText: String, password: String): String {
        val saltBytes: ByteArray = getRandomBytes()

        val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(password.toCharArray(), saltBytes, 40000, 256)
        val secretKey: SecretKey = factory.generateSecret(spec)
        val secretKeySpec = SecretKeySpec(secretKey.encoded, "AES")

        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
        val params: AlgorithmParameters = cipher.parameters
        val ivBytes = params.getParameterSpec(IvParameterSpec::class.java).iv
        val encryptedByteArray: ByteArray = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        val encodedPackage = ByteArray(saltBytes.size + ivBytes.size + encryptedByteArray.size)

        System.arraycopy(saltBytes,
                0,
                encodedPackage,
                0,
                saltBytes.size)
        System.arraycopy(ivBytes,
                0,
                encodedPackage,
                saltBytes.size,
                ivBytes.size)
        System.arraycopy(encryptedByteArray,
                0,
                encodedPackage,
                saltBytes.size + ivBytes.size,
                encryptedByteArray.size)

        return Base64.encodeToString(encodedPackage, Base64.DEFAULT)
    }

    private fun decryptAES(encryptedText: String, password: String, toast: Toast): String {
        try {
            val buffer: ByteBuffer = ByteBuffer.wrap(Base64.decode(encryptedText, Base64.DEFAULT))

            val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

            val saltBytes = ByteArray(getSaltLength())
            buffer.get(saltBytes, 0, saltBytes.size)
            val ivBytes = ByteArray(cipher.blockSize)
            buffer.get(ivBytes, 0, ivBytes.size)
            val encryptedTextBytes = ByteArray(buffer.capacity() - saltBytes.size - ivBytes.size)
            buffer.get(encryptedTextBytes)

            val factory: SecretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            val spec = PBEKeySpec(password.toCharArray(), saltBytes, 40000, 256)
            val secretKey: SecretKey = factory.generateSecret(spec)
            val secretKeySpec = SecretKeySpec(secretKey.encoded, "AES")

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IvParameterSpec(ivBytes))

            val decryptedTextBytes = cipher.doFinal(encryptedTextBytes)

            return String(decryptedTextBytes)
        } catch (e: Exception) {
            var toastCopy = toast
            toastCopy = Toast.makeText(this, e.toString(), Toast.LENGTH_SHORT)
            toastCopy.setGravity(Gravity.BOTTOM, 0, 150)
            toastCopy.show()
            return encryptedText
        }
    }
}
