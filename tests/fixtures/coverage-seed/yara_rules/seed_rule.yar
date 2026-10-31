rule PyThreatAnalyzer_CI_Seed {
    meta:
        description = "Synthetic rule used only to validate CI tooling"
    strings:
        $seed = "PYTHREATANALYZER_CI_SEED"
    condition:
        $seed
}
