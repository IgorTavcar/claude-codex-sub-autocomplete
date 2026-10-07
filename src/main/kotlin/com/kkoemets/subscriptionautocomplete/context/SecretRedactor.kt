package com.kkoemets.subscriptionautocomplete.context

object SecretRedactor {
  private val secretName = "(?:api[_-]?key|token|secret|password|passwd|credential|authorization|cookie)"
  private val assignment = Regex(
    "(?i)^(\\s*(?:export\\s+)?[A-Z0-9_.-]*$secretName[A-Z0-9_.-]*\\s*[:=]\\s*)(.*)$",
  )
  // A quoted value is consumed whole. Stopping at its first space would redact only the scheme of
  // "Bearer <credential>" or the first word of a passphrase and send the rest.
  private val structuredValue = Regex(
    "(?i)([\"']?[A-Z0-9_.-]*$secretName[A-Z0-9_.-]*[\"']?\\s*[:=]\\s*)" +
      "(\"(?:[^\"\\\\]|\\\\.)*\"?|'(?:[^'\\\\]|\\\\.)*'?|[^\\s,}\\]]+)",
  )
  private val basicAuthUrl = Regex("(https?://)[^\\s/@:]+:[^\\s/@]+@", RegexOption.IGNORE_CASE)
  private val authorizationHeader = Regex(
    "(?i)(authorization\\s*[:=]\\s*)(?:[A-Z][A-Z0-9_-]*\\s+)?[^\\s,;\"']+",
  )
  private val cookieHeader = Regex(
    "(?i)((?:set-)?cookie\\s*[:=]\\s*)[^\\s=;,\"']+=[^\\s;,\"']*(?:;\\s*[^\\s=;,\"']+(?:=[^\\s;,\"']*)?)*",
  )
  private val providerToken = Regex(
    "(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|" +
      "glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|" +
      "xox[abeprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|" +
      "npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,})(?![A-Za-z0-9])",
  )
  private val jwt = Regex(
    "(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])",
  )
  private val privateKey = Regex(
    "(?s)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
  )

  fun redact(text: String): String = privateKey.replace(text, "<redacted-private-key>")
    .lineSequence()
    .joinToString("\n") { line ->
      val withoutHeaders = cookieHeader.replace(
        authorizationHeader.replace(line, "${'$'}1<redacted>"),
        "${'$'}1<redacted>",
      )
      val assigned = assignment.matchEntire(withoutHeaders)
      val redactedLine = if (assigned != null) {
        assigned.groupValues[1] + "<redacted>"
      } else {
        structuredValue.replace(withoutHeaders) { match -> match.groupValues[1] + "<redacted>" }
      }
      basicAuthUrl.replace(
        jwt.replace(
          providerToken.replace(
            redactedLine,
            "<redacted-token>",
          ),
          "<redacted-jwt>",
        ),
        "${'$'}1<redacted>@",
      )
    }
}
