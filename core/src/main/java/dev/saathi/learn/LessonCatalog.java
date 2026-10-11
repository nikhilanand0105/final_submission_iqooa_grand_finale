package dev.saathi.learn;

import dev.saathi.util.Json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Versioned, bundled lesson content (assets/lessons/lessons_v1.json). Parsing validates the whole file;
 * a malformed file is rejected as a whole rather than partially shown.
 */
public final class LessonCatalog {

    public static final int SUPPORTED_SCHEMA = 1;
    public static final String DEFAULT_LANGUAGE = "en";
    private static final Pattern ID = Pattern.compile("^[a-z0-9][a-z0-9-]{1,48}$");

    public static class ContentException extends Exception {
        public ContentException(String m) { super(m); }
    }

    public static final class Choice {
        public final String text;
        public final boolean safe;
        public final String feedback;

        Choice(String text, boolean safe, String feedback) {
            this.text = text;
            this.safe = safe;
            this.feedback = feedback;
        }
    }

    /** Lesson text in one language. */
    public static final class Text {
        public final String title, subtitle, intro, scenario, question;
        public final List<String> warningSigns, nextSteps;
        public final List<Choice> choices;

        Text(String title, String subtitle, String intro, String scenario, String question,
             List<String> warningSigns, List<Choice> choices, List<String> nextSteps) {
            this.title = title;
            this.subtitle = subtitle;
            this.intro = intro;
            this.scenario = scenario;
            this.question = question;
            this.warningSigns = Collections.unmodifiableList(warningSigns);
            this.choices = Collections.unmodifiableList(choices);
            this.nextSteps = Collections.unmodifiableList(nextSteps);
        }
    }

    public static final class Lesson {
        public final String id;
        public final int order;
        public final String icon;
        private final Map<String, Text> byLang;

        Lesson(String id, int order, String icon, Map<String, Text> byLang) {
            this.id = id;
            this.order = order;
            this.icon = icon;
            this.byLang = Collections.unmodifiableMap(byLang);
        }

        public boolean hasLanguage(String lang) {
            return byLang.containsKey(lang);
        }

        /** Text in the requested language, or English if that translation does not exist. */
        public Text text(String lang) {
            Text t = byLang.get(lang);
            return t != null ? t : byLang.get(DEFAULT_LANGUAGE);
        }
    }

    public final int schemaVersion;
    public final String contentVersion;
    public final List<Lesson> lessons;

    private LessonCatalog(int schemaVersion, String contentVersion, List<Lesson> lessons) {
        this.schemaVersion = schemaVersion;
        this.contentVersion = contentVersion;
        this.lessons = Collections.unmodifiableList(lessons);
    }

    public Lesson byId(String id) {
        for (Lesson l : lessons) if (l.id.equals(id)) return l;
        return null;
    }

    public Set<String> ids() {
        Set<String> s = new HashSet<>();
        for (Lesson l : lessons) s.add(l.id);
        return s;
    }

    public static LessonCatalog parse(String json) throws ContentException {
        Map<String, Object> root;
        try {
            root = Json.parseObject(json);
        } catch (Json.ParseException e) {
            throw new ContentException("Lesson file is not valid JSON: " + e.getMessage());
        }
        Long schema = Json.lng(root, "schemaVersion");
        if (schema == null || schema.intValue() != SUPPORTED_SCHEMA) throw new ContentException("Unsupported lesson schemaVersion: " + schema);
        String cv = req(root, "contentVersion", "root");
        List<Object> arr = Json.arr(root, "lessons");
        if (arr == null || arr.isEmpty()) throw new ContentException("No lessons in file");
        List<Lesson> out = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (Object o : arr) {
            if (!(o instanceof Map)) throw new ContentException("Lesson entry is not an object");
            @SuppressWarnings("unchecked") Map<String, Object> lm = (Map<String, Object>) o;
            String id = Json.str(lm, "id");
            if (id == null || !ID.matcher(id).matches()) throw new ContentException("Missing or invalid lesson id: " + id);
            if (!ids.add(id)) throw new ContentException("Duplicate lesson id: " + id);
            Long order = Json.lng(lm, "order");
            if (order == null) throw new ContentException(id + ": missing order");
            String icon = Json.str(lm, "icon");
            Map<String, Object> content = Json.obj(lm, "content");
            if (content == null || !content.containsKey(DEFAULT_LANGUAGE)) throw new ContentException(id + ": missing English content");
            Map<String, Text> byLang = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : content.entrySet()) {
                if (!e.getKey().matches("^[a-z]{2}$")) throw new ContentException(id + ": bad language code " + e.getKey());
                if (!(e.getValue() instanceof Map)) throw new ContentException(id + "/" + e.getKey() + ": content is not an object");
                @SuppressWarnings("unchecked") Map<String, Object> tm = (Map<String, Object>) e.getValue();
                byLang.put(e.getKey(), text(tm, id + "/" + e.getKey()));
            }
            out.add(new Lesson(id, order.intValue(), icon == null ? "" : icon, byLang));
        }
        out.sort((a, b) -> Integer.compare(a.order, b.order));
        return new LessonCatalog(schema.intValue(), cv, out);
    }

    private static Text text(Map<String, Object> m, String where) throws ContentException {
        List<String> signs = reqList(m, "warningSigns", where);
        List<String> steps = reqList(m, "nextSteps", where);
        List<Object> ch = Json.arr(m, "choices");
        if (ch == null || ch.size() < 2 || ch.size() > 4) throw new ContentException(where + ": needs 2-4 choices");
        List<Choice> choices = new ArrayList<>();
        int safe = 0;
        for (Object c : ch) {
            if (!(c instanceof Map)) throw new ContentException(where + ": choice is not an object");
            @SuppressWarnings("unchecked") Map<String, Object> cm = (Map<String, Object>) c;
            Boolean s = Json.bool(cm, "safe");
            if (s == null) throw new ContentException(where + ": choice missing 'safe'");
            if (s) safe++;
            choices.add(new Choice(req(cm, "text", where), s, req(cm, "feedback", where)));
        }
        if (safe < 1) throw new ContentException(where + ": no safe choice");
        return new Text(req(m, "title", where), req(m, "subtitle", where), req(m, "intro", where), req(m, "scenario", where),
                req(m, "question", where), signs, choices, steps);
    }

    private static String req(Map<String, Object> m, String k, String where) throws ContentException {
        String v = Json.str(m, k);
        if (v == null || v.trim().isEmpty()) throw new ContentException(where + ": missing '" + k + "'");
        return v;
    }

    private static List<String> reqList(Map<String, Object> m, String k, String where) throws ContentException {
        List<String> v = Json.strList(m, k);
        if (v == null || v.isEmpty()) throw new ContentException(where + ": missing '" + k + "'");
        for (String s : v) if (s.trim().isEmpty()) throw new ContentException(where + ": empty item in '" + k + "'");
        return v;
    }

    // ---- progress helpers (pure, testable) ---------------------------------------------------

    /** Completed lessons counted only if they exist in this catalog (stale ids from older content are ignored). */
    public int completedCount(Set<String> completedIds) {
        int n = 0;
        for (Lesson l : lessons) if (completedIds.contains(l.id)) n++;
        return n;
    }

    /** First lesson (by order) not yet completed, or null when all are complete. */
    public Lesson nextIncomplete(Set<String> completedIds) {
        for (Lesson l : lessons) if (!completedIds.contains(l.id)) return l;
        return null;
    }

    /** Lessons whose text is missing in the given language. */
    public List<String> untranslated(String lang) {
        List<String> out = new ArrayList<>();
        for (Lesson l : lessons) if (!l.hasLanguage(lang)) out.add(l.id);
        return out;
    }
}
