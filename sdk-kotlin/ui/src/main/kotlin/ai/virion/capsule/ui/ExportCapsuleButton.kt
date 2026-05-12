// ExportCapsuleButton — drop-in share affordance for a built capsule.

package ai.virion.capsule.ui

import ai.virion.capsule.core.CapsuleBuilder
import ai.virion.capsule.core.CapsuleVerification
import ai.virion.capsule.core.CapsuleVerifier
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.IosShare
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import java.io.File

@Composable
fun ExportCapsuleButton(
    result: CapsuleBuilder.BuildResult,
    fileProviderAuthority: String,
    label: String = "Share .capsule",
    suggestedFileName: String? = null,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val verification = remember(result) { CapsuleVerifier.verify(result.bytes) }
    val name = suggestedFileName
        ?: "capsule-${result.capsuleId.take(8)}.capsule"

    Row(modifier, verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Button(
            onClick = {
                val outDir = File(ctx.cacheDir, "capsule-exports").apply { mkdirs() }
                val file = File(outDir, name)
                file.writeBytes(result.bytes)
                val uri = FileProvider.getUriForFile(ctx, fileProviderAuthority, file)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "application/octet-stream"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                ctx.startActivity(Intent.createChooser(send, "Share .capsule"))
            },
            enabled = verification.ok,
        ) {
            Icon(Icons.Default.IosShare, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(label)
        }
        Spacer(Modifier.width(12.dp))
        VerifyBadge(verification)
    }
}
