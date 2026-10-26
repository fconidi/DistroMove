from distromove.i18n import LANGUAGES, MESSAGES, tr


def test_i18n_five_languages_same_keys():
    assert set(LANGUAGES) == {"en", "it", "fr", "de", "es"}
    expected = set(MESSAGES["en"])
    assert all(set(MESSAGES[language]) == expected for language in LANGUAGES)


def test_no_empty_translations():
    assert all(value.strip() for catalog in MESSAGES.values() for value in catalog.values())
    assert tr("title", "it") == "DistroMove"
