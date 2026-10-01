-- ResearchChatAI: optional per-study response limit for OpenRouter
--
-- Adds one empty column. Existing studies keep NULL, which means "use the
-- original fixed limit" (1500 tokens, 30 s timeout), so nothing changes for
-- them. New studies get 8000 from Backend/Studies/study-create.php.
--
-- Safe to run before the new code is uploaded: the old code ignores the column.
-- The new code also works without the column (it then behaves as before),
-- but the "Maximum response length" field in the editor can only be saved
-- once the column exists.

ALTER TABLE studies
  ADD COLUMN openrouterMaxTokens VARCHAR(16) DEFAULT NULL AFTER openrouterEnableStreaming;
