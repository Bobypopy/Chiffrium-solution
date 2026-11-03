package com.chiffrium.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Langages reconnus par l'analyseur. L'identifiant est celui exposé dans les rapports et l'API.
 */
public enum Language {
    JAVA("java"),
    KOTLIN("kotlin"),
    SCALA("scala"),
    GROOVY("groovy"),
    PYTHON("python"),
    JAVASCRIPT("javascript"),
    TYPESCRIPT("typescript"),
    GO("go"),
    CSHARP("csharp"),
    C("c"),
    CPP("cpp"),
    PHP("php"),
    RUBY("ruby"),
    RUST("rust"),
    SWIFT("swift"),
    DART("dart"),
    ELIXIR("elixir"),
    PERL("perl"),
    OBJC("objc"),
    SQL("sql"),
    VBNET("vbnet"),
    FSHARP("fsharp"),
    ERLANG("erlang"),
    CONFIG("config"),
    UNKNOWN("unknown");

    private final String id;

    Language(String id) {
        this.id = id;
    }

    @JsonValue
    public String id() {
        return id;
    }

    public static Optional<Language> fromId(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(l -> l.id.equals(normalized)).findFirst();
    }

    @JsonCreator
    static Language fromJson(String value) {
        return fromId(value).orElse(UNKNOWN);
    }
}
