package com.kkoemets.subscriptionautocomplete.provider

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProviderPolicyTest {
  @Test
  fun `defaults to the newest provider models and lists each default first`() {
    assertEquals("opus", ProviderPolicy.DEFAULT_CLAUDE_MODEL)
    assertEquals("gpt-6.1-sol", ProviderPolicy.DEFAULT_CODEX_MODEL)
    assertEquals("low", ProviderPolicy.DEFAULT_CODEX_EFFORT)
    assertEquals(ProviderPolicy.DEFAULT_CLAUDE_MODEL, ProviderPolicy.claudeModels.first())
    assertEquals(ProviderPolicy.DEFAULT_CODEX_MODEL, ProviderPolicy.codexFallbackChoices.first())
    assertEquals(listOf("opus", "sonnet", "fable", "haiku"), ProviderPolicy.claudeModels)
    assertEquals(
      listOf("gpt-6.1-sol", "gpt-6-astra", "gpt-6-sol", "gpt-6-luna"),
      ProviderPolicy.codexFallbackChoices,
    )
  }

  @Test
  fun `retired Codex models stay out of the choices but keep their legacy migration`() {
    assertFalse(ProviderPolicy.LEGACY_CODEX_MODEL in ProviderPolicy.codexFallbackChoices)
    assertTrue(ProviderPolicy.codexFallbackChoices.none { it.startsWith("gpt-5") })
    assertTrue("none" in ProviderPolicy.codexReasoningEfforts)
    assertTrue(ProviderPolicy.LEGACY_CODEX_MODEL in ProviderPolicy.codexNoReasoningModels)
  }
}
