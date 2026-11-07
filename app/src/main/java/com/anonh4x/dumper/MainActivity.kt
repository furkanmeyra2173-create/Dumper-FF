package com.anonh4x.dumper

import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipInputStream

class MainActivity : Activity() {
    private lateinit var output: TextView
    private var selectedUri: Uri? = null
    private var lastReport: JSONObject? = null
    private val pickFile = 4101

    private val maxSingleFileBytes = 300L * 1024L * 1024L
    private val maxTotalExtractBytes = 700L * 1024L * 1024L
    private val maxExtractedFiles = 500

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
        root.addView(actionButton("APK'DEN SO + METADATA ÇIKAR") { extractApkContents() })
        root.addView(actionButton("TXT RAPORU PAYLAŞ") { shareReport("txt") })
        root.addView(actionButton("JSON RAPORU PAYLAŞ") { shareReport("json") })
        output = TextView(this).apply {
            text = "Henüz dosya seçilmedi.\n\nAPK seçip içindeki .so ve global-metadata.dat dosyalarını çıkarabilirsin. Analiz yalnızca seçtiğin dosyalar ve Android'in izin verdiği içeriklerle yapılır."
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
                val name = queryName(uri)
                output.text = "Seçilen dosya:\n" + name + "\n\n" +
                    if (name.endsWith(".apk", true)) {
                        "APK seçildi. İçindeki .so ve global-metadata.dat dosyalarını çıkarmak için APK'DEN SO + METADATA ÇIKAR düğmesine bas."
                    } else {
                        "Dosya analiz için hazır. APK içeriği çıkarma özelliği için bir .apk dosyası seç."
                    }
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
                put("version", "0.2.0")
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
            output.text = "Analiz hatası: " + (e.message ?: "Bilinmeyen hata")
        }
    }

    private fun extractApkContents() {
        val apkUri = selectedUri ?: run {
            output.text = "Önce bir APK dosyası seç."
            return
        }
        val apkName = queryName(apkUri)
        if (!apkName.endsWith(".apk", true)) {
            output.text = "Seçilen dosya APK değil. Önce .apk uzantılı bir dosya seç."
            return
        }

        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val folderName = safeFileName(apkName.removeSuffix(".apk").removeSuffix(".APK")) + "_" + timestamp
        val baseFolder = "Dumper-FF/" + folderName
        val extractedFiles = JSONArray()
        val createdMediaUris = mutableListOf<Uri>()
        val createdLocalFiles = mutableListOf<File>()
        var totalBytes = 0L
        var soCount = 0
        var metadataCount = 0
        var fileCount = 0

        output.text = "APK taranıyor...\n" + apkName + "\n\n.so ve global-metadata.dat aranıyor."

        try {
            val input = contentResolver.openInputStream(apkUri)
                ?: error("APK dosyası açılamadı.")
            ZipInputStream(BufferedInputStream(input)).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (!entry.isDirectory) {
                        val normalizedName = entry.name.replace('\\', '/')
                        val leafName = normalizedName.substringAfterLast('/')
                        val isSo = leafName.endsWith(".so", true)
                        val isMetadata = leafName.equals("global-metadata.dat", true)

                        if (isSo || isMetadata) {
                            val safeParts = safeZipPath(normalizedName)
                            if (safeParts != null) {
                                if (fileCount >= maxExtractedFiles) {
                                    error("Dosya sayısı güvenlik sınırını aştı (" + maxExtractedFiles + ").")
                                }

                                val relativeDirectory = if (safeParts.size > 1) {
                                    baseFolder + "/" + safeParts.dropLast(1).joinToString("/")
                                } else {
                                    baseFolder
                                }
                                val outputName = safeParts.last()
                                var entryBytes = 0L
                                var destinationUri: Uri? = null
                                var destinationFile: File? = null

                                try {
                                    val destinationStream = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                        val values = ContentValues().apply {
                                            put(MediaStore.Downloads.DISPLAY_NAME, outputName)
                                            put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                                            put(
                                                MediaStore.Downloads.RELATIVE_PATH,
                                                Environment.DIRECTORY_DOWNLOADS + "/" + relativeDirectory
                                            )
                                            put(MediaStore.Downloads.IS_PENDING, 1)
                                        }
                                        destinationUri = contentResolver.insert(
                                            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                                            values
                                        ) ?: error("Download klasöründe dosya oluşturulamadı: " + outputName)
                                        contentResolver.openOutputStream(destinationUri!!)
                                            ?: error("Çıkarılan dosyaya yazılamadı: " + outputName)
                                    } else {
                                        val root = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                                            ?: File(filesDir, "Download")
                                        val target = File(root, relativeDirectory + "/" + outputName)
                                        if (!target.canonicalPath.startsWith(root.canonicalPath + File.separator)) {
                                            error("Geçersiz ZIP dosya yolu.")
                                        }
                                        target.parentFile?.mkdirs()
                                        destinationFile = target
                                        target.outputStream()
                                    }

                                    destinationStream.use { out ->
                                        val buffer = ByteArray(64 * 1024)
                                        while (true) {
                                            val read = zip.read(buffer)
                                            if (read < 0) break
                                            entryBytes += read.toLong()
                                            totalBytes += read.toLong()
                                            if (entryBytes > maxSingleFileBytes) {
                                                error("Tek dosya 300 MB sınırını aştı: " + outputName)
                                            }
                                            if (totalBytes > maxTotalExtractBytes) {
                                                error("Toplam çıkarma boyutu 700 MB sınırını aştı.")
                                            }
                                            out.write(buffer, 0, read)
                                        }
                                    }

                                    destinationUri?.let { savedUri ->
                                        val complete = ContentValues().apply {
                                            put(MediaStore.Downloads.IS_PENDING, 0)
                                        }
                                        contentResolver.update(savedUri, complete, null, null)
                                        createdMediaUris.add(savedUri)
                                    }
                                    destinationFile?.let { createdLocalFiles.add(it) }

                                    fileCount++
                                    if (isSo) soCount++
                                    if (isMetadata) metadataCount++
                                    extractedFiles.put(JSONObject().apply {
                                        put("entryName", normalizedName)
                                        put("savedName", outputName)
                                        put("type", if (isSo) "shared-library" else "il2cpp-metadata")
                                        put("sizeBytes", entryBytes)
                                        put("relativeFolder", relativeDirectory)
                                    })
                                } catch (e: Exception) {
                                    destinationUri?.let {
                                        try { contentResolver.delete(it, null, null) } catch (_: Exception) { }
                                    }
                                    destinationFile?.let { it.delete() }
                                    throw e
                                }
                            }
                        }
                    }
                    zip.closeEntry()
                }
            }

            val destination = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                "Download/" + baseFolder
            } else {
                "Android/data/" + packageName + "/files/Download/" + baseFolder
            }
            val report = JSONObject().apply {
                put("tool", "Dumper")
                put("version", "0.2.0")
                put("task", "apk-extraction")
                put("sourceApk", apkName)
                put("extractedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date()))
                put("destination", destination)
                put("sharedObjectCount", soCount)
                put("metadataCount", metadataCount)
                put("fileCount", fileCount)
                put("totalExtractedBytes", totalBytes)
                put("files", extractedFiles)
                put("note", "Selected APK archive only. No protected app data or live game memory is accessed.")
            }
            lastReport = report

            output.text = buildString {
                appendLine("APK çıkarma tamamlandı.")
                appendLine()
                appendLine("APK: " + apkName)
                appendLine(".so dosyası: " + soCount)
                appendLine("global-metadata.dat: " + metadataCount)
                appendLine("Toplam dosya: " + fileCount)
                appendLine("Toplam boyut: " + formatBytes(totalBytes))
                appendLine()
                appendLine("Kayıt konumu:")
                appendLine(destination)
                appendLine()
                if (fileCount == 0) {
                    appendLine("APK içinde eşleşen .so veya global-metadata.dat dosyası bulunamadı.")
                } else {
                    appendLine("Çıkarılan dosyalar:")
                    for (i in 0 until minOf(extractedFiles.length(), 40)) {
                        val item = extractedFiles.getJSONObject(i)
                        appendLine("- " + item.optString("entryName") + " (" + formatBytes(item.optLong("sizeBytes")) + ")")
                    }
                    if (extractedFiles.length() > 40) {
                        appendLine("... ve " + (extractedFiles.length() - 40) + " dosya daha.")
                    }
                }
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                    appendLine()
                    appendLine("Not: Android 10 öncesinde dosyalar uygulamanın harici özel klasörüne kaydedildi.")
                }
            }
        } catch (e: Exception) {
            createdMediaUris.forEach {
                try { contentResolver.delete(it, null, null) } catch (_: Exception) { }
            }
            createdLocalFiles.forEach { it.delete() }
            output.text = "APK çıkarma hatası: " + (e.message ?: "Bilinmeyen hata") +
                "\n\nİşlem sırasında oluşturulan kısmi dosyalar temizlendi."
        }
    }

    private fun safeZipPath(path: String): List<String>? {
        val normalized = path.replace('\\', '/')
        val rawParts = normalized.split('/')
        if (rawParts.any { it == ".." || it == "." }) return null
        val parts = rawParts.filter { it.isNotBlank() }.map { safeFileName(it) }
        return parts.takeIf { it.isNotEmpty() }
    }

    private fun safeFileName(value: String): String {
        val cleaned = value.replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.')
        return cleaned.take(120).ifBlank { "file" }
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return bytes.toString() + " B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        return String.format(Locale.US, "%.1f MB", mb)
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
            output.text = "Önce bir dosyayı analiz et veya APK içeriğini çıkar."
            return
        }
        val body = if (format == "json") report.toString(2) else buildString {
            appendLine("DUMPER ANALYSIS REPORT")
            appendLine("=====================")
            val keys = report.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                appendLine(key + ": " + report.opt(key))
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
