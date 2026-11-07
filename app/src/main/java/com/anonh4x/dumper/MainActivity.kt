package com.anonh4x.dumper

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var output: TextView
    private var selectedUri: Uri? = null
    private var lastReport: JSONObject? = null
    private val pickFile = 4101

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 36, 28, 24)
            setBackgroundColor(0xFF10131B.toInt())
        }
        root.addView(TextView(this).apply {
            text = "DUMPER"
            textSize = 30f
            setTextColor(0xFF62E6FF.toInt())
            gravity = Gravity.CENTER
        })
        root.addView(TextView(this).apply {
            text = "ROOTLESS GAME FILE ANALYZER"
            textSize = 12f
            setTextColor(0xFFB8C5D6.toInt())
            gravity = Gravity.CENTER
        })
        root.addView(actionButton("APK / SO / METADATA SEÇ") { openPicker() })
        root.addView(actionButton("SEÇİLEN DOSYAYI ANALİZ ET") { analyzeSelected() })
        root.addView(actionButton("TXT RAPORU PAYLAŞ") { shareReport("txt") })
        root.addView(actionButton("JSON RAPORU PAYLAŞ") { shareReport("json") })
        output = TextView(this).apply {
            text = "Henüz dosya seçilmedi.\n\nAnaliz yalnızca seçtiğin dosyalar ve Android'in izin verdiği içeriklerle yapılır."
            textSize = 14f
            setTextColor(0xFFE7EDF7.toInt())
            setPadding(4, 22, 4, 22)
        }
        root.addView(ScrollView(this).apply { addView(output) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
    }

    private fun actionButton(label: String, action: () -> Unit) =
        Button(this).apply { text = label; setOnClickListener { action() } }

    private fun openPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, pickFile)
    }

    @Deprecated("Deprecated by Android; retained for broad device compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == pickFile && resultCode == RESULT_OK) {
            selectedUri = data?.data
            selectedUri?.let { uri ->
                try {
                    contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                } catch (_: Exception) { }
                output.text = "Seçilen dosya:\n$uri\n\nAnaliz için hazır."
            }
        }
    }

    private fun analyzeSelected() {
        val uri = selectedUri ?: run {
            output.text = "Önce APK, .so veya global-metadata.dat dosyası seç."
            return
        }
        try {
            val name = queryName(uri)
            val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("Dosya okunamadı.")
            val report = JSONObject().apply {
                put("tool", "Dumper")
                put("version", "0.1.0")
                put("fileName", name)
                put("sizeBytes", bytes.size)
                put("analyzedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
                put("fileType", detectType(name, bytes))
                put("elf", if (isElf(bytes)) elfInfo(bytes) else JSONObject.NULL)
                put("metadata", if (name.endsWith("global-metadata.dat", true)) metadataInfo(bytes) else JSONObject.NULL)
                put("note", "Static file inspection only. No protected app data or live game memory is accessed.")
            }
            lastReport = report
            output.text = report.toString(2)
        } catch (e: Exception) {
            output.text = "Analiz hatası: " + e.message
        }
    }

    private fun queryName(uri: Uri): String {
        var name = uri.lastPathSegment ?: "selected-file"
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (i >= 0) name = c.getString(i) ?: name
            }
        }
        return name
    }

    private fun detectType(name: String, b: ByteArray): String = when {
        isElf(b) -> "ELF shared object / executable"
        name.endsWith(".apk", true) -> "Android APK archive"
        name.equals("global-metadata.dat", true) -> "Unity IL2CPP metadata candidate"
        else -> "Unknown / binary file"
    }

    private fun isElf(b: ByteArray) =
        b.size >= 4 && b[0] == 0x7f.toByte() && b[1] == 0x45.toByte() &&
            b[2] == 0x4c.toByte() && b[3] == 0x46.toByte()

    private fun elfInfo(b: ByteArray): JSONObject {
        val endian = if (b.size > 5) b[5].toInt() and 255 else 1
        fun u16(o: Int): Int {
            if (o + 1 >= b.size) return 0
            val a = b[o].toInt() and 255
            val z = b[o + 1].toInt() and 255
            return if (endian == 2) (a shl 8) or z else a or (z shl 8)
        }
        return JSONObject().apply {
            put("class", when (b.getOrNull(4)?.toInt()?.and(255)) {
                1 -> "ELF32"; 2 -> "ELF64"; else -> "Unknown"
            })
            put("endianness", when (endian) { 1 -> "Little endian"; 2 -> "Big endian"; else -> "Unknown" })
            put("type", u16(16))
            put("machine", u16(18))
            put("headerSizeBytes", if (b.getOrNull(4)?.toInt() == 2) 64 else 52)
        }
    }

    private fun metadataInfo(b: ByteArray): JSONObject {
        val view = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val magic = if (b.size >= 4) view.getInt(0) else 0
        val version = if (b.size >= 8) view.getInt(4) else -1
        return JSONObject().apply {
            put("magicHex", "0x%08X".format(Locale.US, magic))
            put("versionCandidate", version)
            put("headerBytesAvailable", minOf(b.size, 8))
            put("fileSizeBytes", b.size)
            put("warning", "Header candidate only; full metadata layout validation is not implemented yet.")
        }
    }

    private fun shareReport(format: String) {
        val report = lastReport ?: run {
            output.text = "Önce bir dosya seçip analiz et."
            return
        }
        val body = if (format == "json") report.toString(2) else buildString {
            appendLine("DUMPER ANALYSIS REPORT")
            appendLine("=====================")
            val keys = report.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                appendLine("$key: " + report.opt(key))
            }
        }
        val send = Intent(Intent.ACTION_SEND).apply {
            type = if (format == "json") "application/json" else "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "Dumper analysis report")
            putExtra(Intent.EXTRA_TEXT, body)
        }
        startActivity(Intent.createChooser(send, "Raporu paylaş / kaydet"))
    }
}
