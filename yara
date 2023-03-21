rule njrat_rule {
    meta:
        description = "Regla YARA para detectar NJRAT"
        author = "fevar54"
        date = "21-03-2023"
    strings:
        $string1 = "NjRat"
        $string2 = "NJ"
        $string3 = "njrat"
    condition:
        any of them
}
