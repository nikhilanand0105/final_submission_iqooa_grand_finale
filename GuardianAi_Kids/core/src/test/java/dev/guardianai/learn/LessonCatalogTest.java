package dev.guardianai.learn;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class LessonCatalogTest {

    /** Loads the real bundled asset from the app module so content and parser are tested together. */
    static String bundledJson() throws Exception {
        File dir = new File(".").getAbsoluteFile();
        for (int i = 0; i < 6 && dir != null; i++, dir = dir.getParentFile()) {
            File f = new File(dir, "app/src/main/assets/lessons/lessons_v1.json");
            if (f.exists()) return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        }
        throw new IllegalStateException("app/src/main/assets/lessons/lessons_v1.json not found from " + new File(".").getAbsolutePath());
    }

    @Test
    void bundledContentLoadsAndCoversRequiredSubjects() throws Exception {
        LessonCatalog c = LessonCatalog.parse(bundledJson());
        assertEquals(1, c.schemaVersion);
        assertEquals(8, c.lessons.size());
        Set<String> expected = new HashSet<>(Arrays.asList("fake-prizes", "suspicious-links", "otp-passwords", "bullying",
                "private-info-pictures", "keeping-secrets", "private-chat-strangers", "asking-for-help"));
        assertEquals(expected, c.ids());
        for (LessonCatalog.Lesson l : c.lessons) {
            for (String lang : new String[]{"en", "hi"}) {
                assertTrue(l.hasLanguage(lang), l.id + " missing " + lang);
                LessonCatalog.Text t = l.text(lang);
                assertFalse(t.intro.isEmpty());
                assertFalse(t.scenario.isEmpty());
                assertTrue(t.choices.stream().anyMatch(ch -> ch.safe));
                t.choices.forEach(ch -> assertFalse(ch.feedback.isEmpty()));
            }
        }
        assertTrue(c.untranslated("hi").isEmpty());
        assertEquals(8, c.untranslated("ta").size());
        assertEquals("fake-prizes", c.lessons.get(0).id);
    }

    @Test
    void untranslatedFallsBackToEnglishExplicitly() throws Exception {
        LessonCatalog c = LessonCatalog.parse(bundledJson());
        LessonCatalog.Lesson l = c.lessons.get(0);
        assertFalse(l.hasLanguage("ta"));
        assertSame(l.text("en"), l.text("ta"));
    }

    @Test
    void progressHelpers() throws Exception {
        LessonCatalog c = LessonCatalog.parse(bundledJson());
        Set<String> done = new HashSet<>(Arrays.asList("fake-prizes", "removed-old-lesson"));
        assertEquals(1, c.completedCount(done)); // stale ids ignored
        assertEquals("suspicious-links", c.nextIncomplete(done).id);
        assertNull(c.nextIncomplete(c.ids()));
        assertEquals(0, c.completedCount(Collections.emptySet()));
    }

    @Test
    void malformedContentRejected() {
        String[] bad = {
                "", "not json", "{}", "{\"schemaVersion\":2,\"contentVersion\":\"x\",\"lessons\":[]}",
                "{\"schemaVersion\":1,\"contentVersion\":\"x\",\"lessons\":[]}",
                lesson("\"id\":\"Bad Id!\""), lesson("\"id\":\"a1\""),
                "{\"schemaVersion\":1,\"contentVersion\":\"x\",\"lessons\":[" + one("a1", "en", true) + "," + one("a1", "en", true) + "]}",
                "{\"schemaVersion\":1,\"contentVersion\":\"x\",\"lessons\":[" + one("a1", "hi", true) + "]}",
                "{\"schemaVersion\":1,\"contentVersion\":\"x\",\"lessons\":[" + one("a1", "en", false) + "]}",
        };
        for (String b : bad) {
            assertThrows(LessonCatalog.ContentException.class, () -> LessonCatalog.parse(b), b);
        }
    }

    @Test
    void minimalValidLesson() throws Exception {
        LessonCatalog c = LessonCatalog.parse("{\"schemaVersion\":1,\"contentVersion\":\"t\",\"lessons\":[" + one("a1", "en", true) + "]}");
        assertNotNull(c.byId("a1"));
        assertNull(c.byId("missing-id"));
    }

    private static String lesson(String idPart) {
        return "{\"schemaVersion\":1,\"contentVersion\":\"x\",\"lessons\":[{" + idPart + ",\"order\":1,\"content\":{}}]}";
    }

    private static String one(String id, String lang, boolean hasSafe) {
        return "{\"id\":\"" + id + "\",\"order\":1,\"icon\":\"x\",\"content\":{\"" + lang + "\":{"
                + "\"title\":\"t\",\"subtitle\":\"s\",\"intro\":\"i\",\"scenario\":\"sc\",\"question\":\"q\","
                + "\"warningSigns\":[\"w\"],\"nextSteps\":[\"n\"],\"choices\":["
                + "{\"text\":\"a\",\"safe\":" + hasSafe + ",\"feedback\":\"f\"},{\"text\":\"b\",\"safe\":false,\"feedback\":\"f\"}]}}}";
    }
}
