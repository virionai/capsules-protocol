// AddCapsuleButton — drop-in "+ Capsule" affordance for Compose hosts.
//
// Tap → ACTION_OPEN_DOCUMENT → parse → callback with the fully parsed
// capsule and a verification report. Hosts wire this into their own UI.

package ai.virion.capsule.ui

import ai.virion.capsule.core.CapsuleReader
import ai.virion.capsule.core.CapsuleVerification
import ai.virion.capsule.core.CapsuleVerifier
import ai.virion.capsule.core.ParsedCapsule
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@Composable
fun AddCapsuleButton(
    label: String = "+ Capsule",
    allowlist: Set<String> = emptySet(),
    modifier: Modifier = Modifier,
    onOpened: (ParsedCapsule, CapsuleVerification, android.net.Uri) -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        try {
            val bytes = ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IllegalStateException("could not read $uri")
            val parsed = CapsuleReader.parse(bytes)
            val v = CapsuleVerifier.verify(bytes, allowlist)
            onOpened(parsed, v, uri)
            error = null
        } catch (t: Throwable) {
            error = t.message ?: "$t"
        }
    }

    Column(modifier) {
        FilledTonalButton(
            onClick = {
                launcher.launch(arrayOf(
                    "application/octet-stream",
                    "application/zip",
                    "*/*",
                ))
            },
        ) {
            Icon(Icons.Default.AddCircle, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(label)
        }
        error?.let {
            Text(it, color = Color(0xFFB02A1B), modifier = Modifier.padding(top = 4.dp))
        }
    }
}

/** Compact verification badge a host can place beside an opened capsule. */
@Composable
fun VerifyBadge(verification: CapsuleVerification, modifier: Modifier = Modifier) {
    val isOk = verification.ok
    val tone = if (isOk) Color(0xFF2D7A45) else Color(0xFFB02A1B)
    val text = when {
        !isOk -> "verification failed"
        verification.trustedSignerCount > 0 -> "verified · trusted"
        else -> "verified"
    }
    Surface(
        shape = CircleShape,
        color = tone.copy(alpha = 0.12f),
        contentColor = tone,
        modifier = modifier,
    ) {
        Row(
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        ) {
            Icon(
                if (isOk) Icons.Default.CheckCircle else Icons.Default.Warning,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(text, style = MaterialTheme.typography.labelSmall)
        }
    }
}
