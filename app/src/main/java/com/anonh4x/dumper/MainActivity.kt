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
    private val maxAnalyzeFileBytes = 256L * 1024L * 1024L
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
            val bytes = contentResolver.openInputStream(uri)?.use { readBounded(it, maxAnalyzeFileBytes) }
                ?: error("Dosya okunamadı.")
            val report = JSONObject().apply {
                put("tool", "Dumper")
                put("version", "0.3.0")
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
                put("version", "0.3.0")
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

    private fun readBounded(input: java.io.InputStream, limitBytes: Long): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count.toLong()
            if (total > limitBytes) {
                throw IllegalArgumentException("Analiz dosyası " + formatBytes(limitBytes) + " sınırını aşıyor.")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun metadataInfo(b: ByteArray): JSONObject {
        val magicExpected = 0xFAB11BAFL
        val tablesNames = listOf(
            "stringLiterals", "stringLiteralData", "strings", "events", "properties",
            "methods", "parameterDefaultValues", "fieldDefaultValues", "defaultValues",
            "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters",
            "fields", "genericParameters", "genericParameterConstraints", "genericContainers",
            "nestedTypes", "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions",
            "images", "assemblies", "metadataUsageLists", "metadataUsagePairs", "fieldRefs",
            "referencedAssemblies", "attributesInfo", "attributeTypes",
            "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
            "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions"
        )

        if (b.size < 16) {
            return JSONObject().apply {
                put("valid", false)
                put("fileSizeBytes", b.size)
                put("error", "Dosya metadata başlığı için çok kısa.")
            }
        }

        val view = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val magic = view.getInt(0).toLong() and 0xffffffffL
        val version = view.getInt(4)
        val firstTableOffset = view.getInt(8)

        if (magic != magicExpected) {
            return JSONObject().apply {
                put("valid", false)
                put("magicHex", "0x%08X".format(Locale.US, magic))
                put("versionCandidate", version)
                put("fileSizeBytes", b.size)
                put("error", "Unity IL2CPP metadata magic değeri eşleşmiyor.")
            }
        }

        val headerShapeValid = firstTableOffset >= 16 &&
            firstTableOffset <= b.size &&
            (firstTableOffset - 8) % 8 == 0
        if (!headerShapeValid) {
            return JSONObject().apply {
                put("valid", false)
                put("magicHex", "0x%08X".format(Locale.US, magic))
                put("versionCandidate", version)
                put("firstTableOffset", firstTableOffset)
                put("fileSizeBytes", b.size)
                put("error", "İlk tablo ofseti geçerli bir metadata başlık uzunluğu oluşturmuyor.")
            }
        }

        val pairCount = minOf(tablesNames.size, (firstTableOffset - 8) / 8)
        val tableRanges = mutableListOf<LongArray>()
        val tablesJson = JSONArray()
        var invalidTableCount = 0

        for (i in 0 until pairCount) {
            val position = 8 + i * 8
            val offset = view.getInt(position)
            val sizeOrCount = view.getInt(position + 4)
            val isCountField = i == 27 || i == 28
            val rangeValid = offset >= 0 && sizeOrCount >= 0 &&
                if (isCountField) {
                    offset.toLong() <= b.size.toLong() && sizeOrCount <= 50_000_000
                } else {
                    offset.toLong() <= b.size.toLong() &&
                        sizeOrCount.toLong() <= b.size.toLong() - offset.toLong()
                }

            if (!rangeValid) invalidTableCount++
            tableRanges.add(longArrayOf(offset.toLong(), sizeOrCount.toLong()))
            tablesJson.put(JSONObject().apply {
                put("index", i)
                put("name", tablesNames[i])
                put("offset", offset)
                put(if (isCountField) "count" else "sizeBytes", sizeOrCount)
                put("rangeValid", rangeValid)
            })
        }

        fun tableRange(index: Int): LongArray? {
            if (index !in tableRanges.indices) return null
            val values = tableRanges[index]
            val offset = values[0]
            val size = values[1]
            if (offset < 0L || size < 0L || offset > b.size.toLong() ||
                size > b.size.toLong() - offset) return null
            return longArrayOf(offset, size)
        }

        val literalTable = tableRange(0)
        val literalDataTable = tableRange(1)
        val stringsTable = tableRange(2)
        val coreTablesValid = literalTable != null && literalDataTable != null && stringsTable != null

        val stringPoolJson = JSONObject()
        if (stringsTable != null) {
            val start = stringsTable[0].toInt()
            val end = (stringsTable[0] + stringsTable[1]).toInt()
            var cursor = start
            var stringCount = 0
            val preview = JSONArray()
            while (cursor < end) {
                var terminator = cursor
                while (terminator < end && b[terminator] != 0.toByte()) terminator++
                val length = terminator - cursor
                if (length > 0) {
                    stringCount++
                    if (preview.length() < 80 && length <= 4096) {
                        val value = String(b, cursor, length, Charsets.UTF_8)
                        val printable = value.count {
                            it == '\t' || it == '\n' || it == '\r' || it >= ' '
                        }
                        if (value.isNotBlank() && printable.toDouble() / value.length.toDouble() >= 0.85) {
                            preview.put(if (value.length > 180) value.take(180) + "…" else value)
                        }
                    }
                }
                cursor = if (terminator < end) terminator + 1 else end
            }
            stringPoolJson.put("offset", start)
            stringPoolJson.put("sizeBytes", stringsTable[1])
            stringPoolJson.put("nonEmptyStringCount", stringCount)
            stringPoolJson.put("preview", preview)
        } else {
            stringPoolJson.put("available", false)
        }

        val literalsJson = JSONObject()
        if (literalTable != null && literalDataTable != null) {
            val tableSize = literalTable[1]
            val recordSize = 8L
            var validLiteralCount = 0
            val preview = JSONArray()
            val records = tableSize / recordSize
            for (i in 0 until minOf(records, 2_000_000L).toInt()) {
                val recordPos = (literalTable[0] + i.toLong() * recordSize).toInt()
                val length = view.getInt(recordPos)
                val dataIndex = view.getInt(recordPos + 4)
                val dataSize = literalDataTable[1]
                val valid = length >= 0 && length <= 1_048_576 && dataIndex >= 0 &&
                    dataIndex.toLong() <= dataSize && length.toLong() <= dataSize - dataIndex.toLong()
                if (valid) {
                    validLiteralCount++
                    if (preview.length() < 40 && length > 0) {
                        val stringStart = (literalDataTable[0] + dataIndex.toLong()).toInt()
                        val value = String(b, stringStart, length, Charsets.UTF_8)
                        val printable = value.count {
                            it == '\t' || it == '\n' || it == '\r' || it >= ' '
                        }
                        if (value.isNotBlank() && printable.toDouble() / value.length.toDouble() >= 0.85) {
                            preview.put(if (value.length > 180) value.take(180) + "…" else value)
                        }
                    }
                }
            }
            literalsJson.put("recordSizeBytes", recordSize)
            literalsJson.put("tableSizeBytes", tableSize)
            literalsJson.put("tableAligned", tableSize % recordSize == 0L)
            literalsJson.put("recordCount", records)
            literalsJson.put("validRecordCount", validLiteralCount)
            literalsJson.put("preview", preview)
        } else {
            literalsJson.put("available", false)
        }

        return JSONObject().apply {
            put("valid", coreTablesValid && invalidTableCount == 0)
            put("magicHex", "0x%08X".format(Locale.US, magic))
            put("version", version)
            put("knownVersionRange", version in 16..31)
            put("fileSizeBytes", b.size)
            put("headerBytes", firstTableOffset)
            put("headerPairCount", pairCount)
            put("tableDirectory", tablesJson)
            put("invalidTableRangeCount", invalidTableCount)
            put("stringPool", stringPoolJson)
            put("stringLiterals", literalsJson)
            put("parserStage", "Header validation, table directory, UTF-8 string pool and string literal records")
            put("decodedTypes", 0)
            put("decodedMethods", 0)
            put("decodedFields", 0)
            put("note", "This build reads static metadata tables and strings only. Type/method/field record decoding is not yet enabled; no live process memory or protected app data is accessed.")
            if (!coreTablesValid) {
                put("warning", "One or more required core table ranges are invalid.")
            } else if (version !in 16..31) {
                put("warning", "Metadata version is outside the currently recognized version range; table layout needs additional verification.")
            } else if (invalidTableCount > 0) {
                put("warning", "Some optional table ranges are invalid and were marked in tableDirectory.")
            }
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
