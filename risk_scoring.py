


"""
Motor de scoring correlacionado + capas individuales.

FIX BUG-5: nueva capa 'similarity' en calculate_layered_risk(): consume
tlsh_match / ssdeep_match (que check_reputation() SIEMPRE rellena desde el
FIX BUG #1) y suma +20 por cada uno. Antes la capa Similarity prometida en
el motor v2 no existía y esos matches no sumaban nada.

FIX C: el imphash se registra en la capa Hash de forma INDEPENDIENTE (no en
un elif): si un archivo matchea por SHA256 y además por imphash, el usuario
ve ambos hallazgos (el score no cambia: max(score, 60)).
"""
from typing import Dict, List, Tuple
from dataclasses import dataclass

# K4: constantes y umbrales centralizados en risk_levels.py.
from risk_levels import (
    LEVEL_RANK, ARCHIVE_LEVEL_WEIGHT, SEVERITY_MAP, WHITELIST_SCORE_CAP,
    DROPPER_MAX_POINTS, level_for_score,
)

try:
    from analysis_utils import is_high_entropy_expected
except ImportError:
    def is_high_entropy_expected(file_path):
        return False


# Alias privados conservados por compatibilidad (fuente: risk_levels.py).
_ARCHIVE_LEVEL_WEIGHT = ARCHIVE_LEVEL_WEIGHT


def _yara_severity_weight(severity):
    if isinstance(severity, str):
        severity = severity.lower()
    return SEVERITY_MAP.get(severity, SEVERITY_MAP['low'])


def calculate_risk_score(virus_results=None, script_results=None, ai_results=None):
    """Devuelve (score 0-100, nivel_de_riesgo, [indicadores])."""
    virus_results = virus_results or {}
    script_results = script_results or {}
    ai_results = ai_results or {}

    score = 0
    indicators = []

    reputation = virus_results.get('reputation', {}) or {}
    # N-07: check_reputation() ya rellena sha1_match, pero aquí solo se
    # miraban md5/sha256. Una base con hashes SOLO en SHA-1 producía
    # un falso negativo (score 0) para malware conocido.
    hash_known_bad = bool(
        reputation.get('sha256_match')
        or reputation.get('sha1_match')
        or reputation.get('md5_match')
    )

    whitelist = virus_results.get('whitelist', {}) or {}
    is_whitelisted = bool(whitelist.get('is_whitelisted')) and not hash_known_bad
    # N-09(a): Authenticode no cubre datos anexados tras la tabla de
    # certificados; un PE firmado con payload añadido NO conserva el amortiguador.
    appended_after_signature = bool(
        (virus_results.get('overlay') or {}).get('appended_after_signature'))
    if is_whitelisted and appended_after_signature:
        is_whitelisted = False

    # ---- Certeza absoluta: hash conocido malicioso ----
    if hash_known_bad:
        score += 100
        indicators.append("HASH_KNOWN_BAD")
        return min(score, 100), _level_for_score(min(score, 100)), indicators

    # ---- NUEVO: imphash coincide con muestra conocida ----
    if reputation.get('imphash_match'):
        score += 30
        indicators.append("IMPHASH_MATCH")

    # ---- YARA ----
    yara_matches = (virus_results.get('yara', {}) or {}).get('matches', []) or []
    yara_score = 0
    yara_max_weight = 0
    yara_rule_names = []
    for match in yara_matches:
        severity = (match.get('meta', {}) or {}).get('severity', 'low')
        yara_rule_names.append(f"{match.get('rule', '?')}({severity})")
        yara_score += _yara_severity_weight(severity)
        yara_max_weight = max(yara_max_weight, _yara_severity_weight(severity))

    file_size = (((virus_results.get('ml_prediction') or {}).get('features')) or {}).get('size', 0)
    is_large_file = file_size > 100 * 1024 * 1024

    if is_large_file and len(yara_matches) == 1 and yara_score < 40:
        indicators.append(f"YARA_MATCH_LOW_CONFIDENCE({yara_rule_names[0]}, archivo grande, no puntuado)")
    else:
        if yara_matches:
            indicators.append(f"YARA_MATCH({', '.join(yara_rule_names[:5])})")
        score += min(yara_score, 70)

    # ---- Análisis estático ----
    static = virus_results.get('static_analysis', {}) or {}
    suspicious_static = static.get('suspicious', []) or []
    if suspicious_static:
        indicators.append(f"STATIC_SUSPICIOUS(x{len(suspicious_static)})")
    score += min(len(suspicious_static) * 5, 25)

    # ---- NUEVO: Overlay PE (payload oculto al final) ----
    if appended_after_signature:
        score += 25
        indicators.append("PE_DATA_AFTER_SIGNATURE")

    overlay = virus_results.get('overlay')
    if overlay and overlay.get('is_suspicious'):
        score += 15
        indicators.append("PE_OVERLAY_SUSPICIOUS")
        if overlay.get('is_pe'):
            score += 20
            indicators.append("OVERLAY_CONTAINS_PE")
        if overlay.get('is_zip'):
            score += 10
            indicators.append("OVERLAY_CONTAINS_ZIP")

    # ---- NUEVO: Transiciones abruptas de entropía por ventanas ----
    ent = virus_results.get('entropy_windows') or {}
    n_trans = int(ent.get('suspicious_transitions', 0) or 0)
    if n_trans > 0:
        score += min(n_trans * 5, 20)
        indicators.append(f"ENTROPY_TRANSITIONS(x{n_trans})")

    # BUGFIX: entropía máxima sostenida (sin transición abrupta) también es
    # indicador de empaquetado/cifrado. calculate_layered_risk() ya lo
    # puntuaba en su capa 'entropy' (>7.8 => +30), pero esta función
    # (la que fija el risk_score/risk_level/indicators de nivel superior
    # que consumen cli.py/main.py, JSON y CSV) no lo consideraba en
    # absoluto: un archivo con entropía sostenida muy alta podía terminar
    # en "SIN RIESGO DETECTADO" en el campo principal mientras layer_scores
    # y explanation.summary ya mostraban ALTO. Se alinea el umbral con el
    # de calculate_layered_risk.
    if ent.get('max_entropy', 0) > 7.8:
        score += 15
        indicators.append(f"ENTROPY_MAX_HIGH({ent['max_entropy']:.2f})")

    # BUGFIX: la prueba de compresibilidad (test_compression_ratio /
    # 'compression' en virus_results) se calcula y se usa para generar la
    # explicación Explainable AI ("Packer_datos_no_compresibles", MITRE
    # T1027.002) pero nunca sumaba al risk_score/risk_level/indicators de
    # nivel superior. Resultado observado en testing: un PE con overlay de
    # datos no compresibles (indicador clásico de packer/cifrado) obtenía
    # risk_score=0 / "SIN RIESGO DETECTADO" pese a que explanation.summary
    # ya lo marcaba como ALTO. Se puntúa aquí para que ambos canales sean
    # consistentes.
    compression = virus_results.get('compression') or {}
    if compression.get('likely_packed'):
        score += 15
        indicators.append("LIKELY_PACKED(low_compressibility)")

    # ---- NUEVO: Análisis de archivo comprimido ----
    arch = virus_results.get('archive_analysis') or {}
    if arch.get('is_password_protected'):
        score += 20
        indicators.append("ARCHIVE_PASSWORD_PROTECTED")
    arch_weight = _ARCHIVE_LEVEL_WEIGHT.get(arch.get('risk_level', 'BENIGNO'), 0)
    if arch_weight:
        score += arch_weight
        indicators.append(f"ARCHIVE_{arch['risk_level']}")

    # ---- ML / heurística ----
    ml = virus_results.get('ml_prediction', {}) or {}
    if ml.get('prediction') in ('MALICIOUS', 'SOSPECHOSO'):
        ml_weight = ml.get('score', 1) * 5 if ml.get('method') == 'heuristic' else 15
        score += min(ml_weight, 20)
        indicators.append(f"ML_{ml['prediction']}")

    # ---- Documentos ----
    doc = virus_results.get('document_analysis', {}) or {}
    if doc.get('has_macros') and doc.get('macro_keywords'):
        score += 30
        indicators.append("MACRO_SUSPICIOUS")
    elif doc.get('has_macros'):
        score += 5
        indicators.append("MACRO_PRESENT")
    if doc.get('type') == 'PDF' and doc.get('suspicious'):
        score += 25
        indicators.append("PDF_SUSPICIOUS")

    # ---- Strings ----
    strings_info = virus_results.get('strings', {}) or {}
    file_path_for_container_check = virus_results.get('file')
    strings_low_confidence = (is_high_entropy_expected(file_path_for_container_check)
                              if file_path_for_container_check else False)

    if strings_info.get('suspicious_commands') and not strings_low_confidence:
        score += 10
        indicators.append("SUSPICIOUS_COMMAND_STRING")
    n_urls = len(strings_info.get('urls', []))
    n_ips = len(strings_info.get('ips', []))

    if virus_results.get('polyglot'):
        score += 25
        indicators.append("POLYGLOT_FILE")

    # ---- Correlación script ----
    network = (script_results.get('network', {}) or {}).get('count', 0)
    persistence = (script_results.get('persistence', {}) or {}).get('count', 0)
    obfuscation = (script_results.get('obfuscation', {}) or {}).get('count', 0)

    if network > 0 and persistence > 0:
        score += 50
        indicators.append("COMBO_NETWORK+PERSISTENCE")
    if obfuscation > 3 and network > 0:
        score += 30
        indicators.append("COMBO_OBFUSCATION+NETWORK")
    if (n_urls > 0 or n_ips > 0) and persistence > 0 and not strings_low_confidence:
        score += 20
        indicators.append("COMBO_EMBEDDED_NETWORK+SCRIPT_PERSISTENCE")

    # ---- N-03: señales del analizador de scripts antes ignoradas ----
    # analyze_script() devuelve total_risk_score/risk_level, la categoría
    # 'system' y (para PowerShell) powershell_analysis, pero aquí solo se
    # miraban network/persistence/obfuscation. Un .ps1 con IEX +
    # DownloadString + -enc quedaba en BAJO(16) pese a que el analizador lo
    # marcaba como ALTO.
    system_calls = (script_results.get('system', {}) or {}).get('count', 0)
    if system_calls > 0:
        score += min(system_calls * 3, 15)
        indicators.append("SCRIPT_SYSTEM_CALL")

    ps_analysis = script_results.get('powershell_analysis') or {}
    ps_suspicious = len(ps_analysis.get('suspicious', []) or [])
    if ps_suspicious > 0:
        score += min(ps_suspicious * 6, 30)
        indicators.append("POWERSHELL_SUSPICIOUS")
    if ps_suspicious >= 2 and (n_urls > 0 or n_ips > 0) and not strings_low_confidence:
        score += 25
        indicators.append("COMBO_POWERSHELL_DOWNLOAD")

    ast_analysis = script_results.get('ast_analysis') or {}
    ast_dynamic = len(ast_analysis.get('dynamic_exec', []) or [])
    if ast_dynamic > 0:
        score += min(ast_dynamic * 5, 15)
        indicators.append("SCRIPT_DYNAMIC_EXEC")
    ast_calls = len(ast_analysis.get('suspicious_calls', []) or [])
    if ast_calls > 0:
        score += min(ast_calls * 2, 10)
        indicators.append("SCRIPT_SUSPICIOUS_IMPORT")

    # N-03 (restante): JS/VBS no tenían consumidores; un .js dropper con
    # ActiveXObject + eval(unescape()) puntuaba BAJO. web_script_analysis
    # lo llena el ScriptAnalyzer para .js/.vbs/.vbe/.jse/.hta/.wsf/.au3.
    web_analysis = script_results.get('web_script_analysis') or {}
    web_suspicious = len(web_analysis.get('suspicious', []) or [])
    if web_suspicious > 0:
        score += min(web_suspicious * 5, 25)
        indicators.append("WEB_SCRIPT_SUSPICIOUS")

    # total_risk_score es el agregado del analizador; se usa como suelo
    # acotado solo para categorías no cubiertas arriba (p.ej. 'encoding'),
    # evitando recontar lo ya sumado.
    script_total = script_results.get('total_risk_score', 0) or 0
    if script_total > 0 and not (system_calls or ps_suspicious or ast_dynamic or ast_calls or web_suspicious):
        score += min(script_total, 15)
        indicators.append("SCRIPT_RISK_AGGREGATE")

    # ---- Comportamiento estático ----
    behavior = virus_results.get('behavior_analysis', {}) or {}
    behavior_network = len(behavior.get('network_indicators', []))
    behavior_persistence = len(behavior.get('persistence_indicators', []))
    behavior_anti_analysis = len(behavior.get('anti_analysis_indicators', []))
    behavior_low_confidence = behavior.get('low_confidence_container', False)

    if not behavior_low_confidence:
        if behavior_network > 0:
            score += min(behavior_network * 3, 15)
            indicators.append("BEHAVIOR_NETWORK_IOC")
        if behavior_persistence > 0:
            score += min(behavior_persistence * 5, 15)
            indicators.append("BEHAVIOR_PERSISTENCE_IOC")
        if behavior_anti_analysis > 0:
            score += min(behavior_anti_analysis * 5, 10)
            indicators.append("BEHAVIOR_ANTI_ANALYSIS_IOC")
        if behavior_network > 0 and behavior_persistence > 0:
            score += 25
            indicators.append("COMBO_BEHAVIOR_NETWORK+PERSISTENCE")
    else:
        if behavior_persistence > 0:
            score += min(behavior_persistence * 2, 5)
            indicators.append("BEHAVIOR_PERSISTENCE_IOC(peso reducido, baja confianza del formato)")
        if behavior_network or behavior_anti_analysis:
            indicators.append("BEHAVIOR_IOC_LOW_CONFIDENCE(red/anti-análisis no puntuados, baja confianza del formato)")

    # R-01: cadenas descarga+ejecución (wget|curl ... | sh, chmod +x tras
    # descargar, base64 -d | sh). Se puntúan SIEMPRE, también en ELF y
    # scripts donde los IOC sueltos son de baja confianza.
    dropper = behavior.get('dropper_indicators') or []
    if dropper:
        score += min(sum(int(d.get('points', 0)) for d in dropper), DROPPER_MAX_POINTS)
        indicators.append("BEHAVIOR_DROPPER_PATTERN(" + ",".join(
            str(d.get('id')) for d in dropper) + ")")

    # ---- Prompt IA embebido ----
    if ai_results.get('prompt_detected'):
        score += 5
        indicators.append("EMBEDDED_AI_PROMPT")

    score = min(score, 100)

    # ---- Amortiguador whitelist ----
    # N-09(c): el método determina qué atesta la whitelist. 'hash_db',
    # 'nsrl' y 'package_manager' atestan ESTE contenido exacto; 'authenticode'
    # solo atesta el origen del firmante (certificados robados, drivers
    # vulnerables firmados): con YARA alto/crítico no se amortigua.
    if is_whitelisted and score > 0:
        yara_strong = yara_max_weight >= SEVERITY_MAP['high']
        if whitelist.get('method') == 'authenticode' and yara_strong:
            indicators.append("WHITELIST_NO_APLICADA(firma válida pero YARA alto/crítico)")
        else:
            indicators.append(f"WHITELISTED({whitelist.get('method', '?')})")
            score = min(score, WHITELIST_SCORE_CAP)

    return score, _level_for_score(score), indicators


_level_for_score = level_for_score


# ================================================================
# Score por capas (Explainable AI)
# ================================================================

_LEVEL_RANK_LAYERED = LEVEL_RANK


@dataclass
class LayerScore:
    """Score individual para una capa de análisis."""
    name: str
    score: int
    confidence: float
    findings: List[str]


def calculate_layered_risk(virus_results: Dict, script_results: Dict = None,
                            ai_results: Dict = None) -> Tuple[int, str, List[str], Dict[str, LayerScore]]:
    """Calcula el desglose de riesgo por capas para la UI "Explainable AI"
    (score/confianza/hallazgos por capa: hash, yara, static, entropy,
    overlay, archive, similarity).

    FIX BUG #3 (score duplicado/divergente): esta función solía calcular
    su PROPIO score final y nivel de riesgo con una fórmula de suma
    acotada por confianza, totalmente independiente de la de
    calculate_risk_score() (que además correlaciona combinaciones -p.ej.
    red+persistencia- y es la que de verdad usan cli.py/main.py para el
    campo 'risk_score'/'risk_level' mostrado al usuario). Las dos
    fórmulas podían dar resultados distintos para el mismo archivo (se
    verificó: overlay+entropía sospechosos daban ALTO/60 en una y
    CRÍTICO/98 en la otra), y encima se ejecutaban las DOS en cada
    escaneo (coste de CPU duplicado para nada).

    Ahora el score/nivel/indicadores FINALES que devuelve esta función
    son siempre los de calculate_risk_score() (única fuente de verdad);
    esta función solo aporta el desglose por capa para mostrarlo en la UI.
    """
    virus_results = virus_results or {}
    layers: Dict[str, LayerScore] = {}

    # Capa Hash (incluye imphash)
    hash_layer = LayerScore('Hash Reputation', 0, 1.0, [])
    rep = virus_results.get('reputation', {}) or {}
    if rep.get('sha256_match'):
        hash_layer.score = 100
        hash_layer.findings.append('SHA256 en blacklist')
    elif rep.get('sha1_match'):
        # N-07: una base poblada solo con SHA-1 también debe puntuar.
        hash_layer.score = 95
        hash_layer.findings.append('SHA1 en blacklist')
    elif rep.get('md5_match'):
        hash_layer.score = 90
        hash_layer.findings.append('MD5 en blacklist')

    # FIX C: imphash se registra INDEPENDIENTE del sha256/md5 (no elif).
    # Un match por imphash es información relevante aunque también matchee
    # el hash completo; max() no altera el score de un hash fuerte.
    if rep.get('imphash_match'):
        hash_layer.score = max(hash_layer.score, 60)
        hash_layer.findings.append('Imphash coincide con muestra conocida')
    layers['hash'] = hash_layer

    # Capa YARA
    yara_layer = LayerScore('YARA Rules', 0, 0.9, [])
    yara = virus_results.get('yara', {}) or {}
    for match in yara.get('matches', []) or []:
        sev = (match.get('meta', {}) or {}).get('severity', 'low')
        yara_layer.score += _yara_severity_weight(sev)
        yara_layer.findings.append(f"Match: {match.get('rule', '?')}")
    yara_layer.score = min(yara_layer.score, 100)
    layers['yara'] = yara_layer

    # Capa Estática
    static_layer = LayerScore('Static Analysis', 0, 0.8, [])
    static = virus_results.get('static_analysis', {}) or {}
    suspicious = static.get('suspicious', []) or []
    static_layer.score = min(len(suspicious) * 5, 100)
    static_layer.findings = suspicious[:5]
    layers['static'] = static_layer

    # Capa Entropía
    entropy_layer = LayerScore('Entropy Analysis', 0, 0.6, [])
    ent = virus_results.get('entropy_windows', {}) or {}
    if ent.get('suspicious_transitions', 0) > 0:
        entropy_layer.score += 40
        entropy_layer.findings.append(
            f"Transición de entropía abrupta ({ent['suspicious_transitions']} transición(es))")
    if ent.get('max_entropy', 0) > 7.8:
        entropy_layer.score += 30
        entropy_layer.findings.append(f"Entropía máxima {ent['max_entropy']:.2f}")
    entropy_layer.score = min(entropy_layer.score, 100)
    layers['entropy'] = entropy_layer

    # Capa Overlay
    overlay_layer = LayerScore('PE Overlay', 0, 0.7, [])
    overlay = virus_results.get('overlay')
    if overlay and overlay.get('is_suspicious'):
        overlay_layer.score += 40
        overlay_layer.findings.append(
            f"Overlay de {overlay['size']} bytes (entropía {overlay['entropy']:.2f})")
        if overlay.get('is_pe'):
            overlay_layer.score += 40
            overlay_layer.findings.append("Overlay contiene un PE embebido")
        if overlay.get('is_zip'):
            overlay_layer.score += 20
            overlay_layer.findings.append("Overlay contiene un ZIP embebido")
    overlay_layer.score = min(overlay_layer.score, 100)
    layers['overlay'] = overlay_layer

    # Capa Archivo Comprimido
    archive_layer = LayerScore('Archive Analysis', 0, 0.7, [])
    arch = virus_results.get('archive_analysis') or {}
    if arch:
        if arch.get('is_password_protected'):
            archive_layer.score += 30
            archive_layer.findings.append('Protegido con contraseña')
        for sp in arch.get('suspicious_patterns', []) or []:
            archive_layer.findings.append(sp)
        if arch.get('risk_level') == 'CRÍTICO':
            archive_layer.score = 100
            archive_layer.findings.append('Contenido crítico detectado')
        agg = arch.get('aggregated_risk')
        if agg and _LEVEL_RANK_LAYERED.get(agg, 0) >= 3:
            archive_layer.score = max(archive_layer.score, 70)
            archive_layer.findings.append(f"Miembro interno con riesgo {agg}")
    archive_layer.score = min(archive_layer.score, 100)
    layers['archive'] = archive_layer

    # Capa Similarity (FIX BUG-5): fuzzy matching TLSH/ssdeep.
    # check_reputation() siempre rellena estas claves (FIX BUG #1); sin esta
    # capa esos matches no contribuían al score por capas.
    similarity_layer = LayerScore('Fuzzy Similarity', 0, 0.8, [])
    if rep.get('tlsh_match'):
        similarity_layer.score += 20
        similarity_layer.findings.append('TLSH_SIMILARITY_MATCH')
    if rep.get('ssdeep_match'):
        similarity_layer.score += 20
        similarity_layer.findings.append('SSDEEP_SIMILARITY_MATCH')
    similarity_layer.score = min(similarity_layer.score, 100)
    layers['similarity'] = similarity_layer

    # Capas para las señales externas al análisis de virus. Sus scores son
    # contribuciones brutas antes del cap global/whitelist, por lo que no
    # deben sumarse para reconstruir el risk_score final.
    script_results = script_results or {}
    script_layer = LayerScore('Script Correlations', 0, 0.8, [])
    network = (script_results.get('network', {}) or {}).get('count', 0)
    persistence = (script_results.get('persistence', {}) or {}).get('count', 0)
    obfuscation = (script_results.get('obfuscation', {}) or {}).get('count', 0)
    if network > 0 and persistence > 0:
        script_layer.score += 50
        script_layer.findings.append('Correlación de red y persistencia (+50)')
    if obfuscation > 3 and network > 0:
        script_layer.score += 30
        script_layer.findings.append('Ofuscación y red (+30)')
    # Esta correlación combina IOC embebidos del análisis de virus con
    # persistencia extraída del script; se refleja aquí para hacer visible
    # la aportación del análisis de script al total.
    strings_info = virus_results.get('strings', {}) or {}
    n_urls = len(strings_info.get('urls', []) or [])
    n_ips = len(strings_info.get('ips', []) or [])
    file_path_for_container_check = virus_results.get('file')
    strings_low_confidence = (is_high_entropy_expected(file_path_for_container_check)
                              if file_path_for_container_check else False)
    if (n_urls > 0 or n_ips > 0) and persistence > 0 and not strings_low_confidence:
        script_layer.score += 20
        script_layer.findings.append('IOC embebido y persistencia (+20)')
    # N-03: reflejar también las señales de script antes ignoradas.
    system_calls = (script_results.get('system', {}) or {}).get('count', 0)
    if system_calls > 0:
        script_layer.score += min(system_calls * 3, 15)
        script_layer.findings.append(f'Llamadas a sistema del script (+{min(system_calls * 3, 15)})')
    ps_suspicious = len((script_results.get('powershell_analysis') or {}).get('suspicious', []) or [])
    if ps_suspicious > 0:
        script_layer.score += min(ps_suspicious * 6, 30)
        script_layer.findings.append(f'Cmdlets PowerShell sospechosos (+{min(ps_suspicious * 6, 30)})')
    if ps_suspicious >= 2 and (n_urls > 0 or n_ips > 0) and not strings_low_confidence:
        script_layer.score += 25
        script_layer.findings.append('Descarga PowerShell vía red (+25)')
    ast_analysis = script_results.get('ast_analysis') or {}
    ast_dynamic = len(ast_analysis.get('dynamic_exec', []) or [])
    if ast_dynamic > 0:
        script_layer.score += min(ast_dynamic * 5, 15)
        script_layer.findings.append(f'Ejecución dinámica AST (+{min(ast_dynamic * 5, 15)})')
    # N-03 (restante): señales JS/VBS/HTA.
    web_suspicious = len((script_results.get('web_script_analysis') or {}).get('suspicious', []) or [])
    if web_suspicious > 0:
        script_layer.score += min(web_suspicious * 5, 25)
        script_layer.findings.append(f'Marcadores WSH/ActiveX en JS/VBS (+{min(web_suspicious * 5, 25)})')
    script_layer.score = min(script_layer.score, 100)
    layers['script'] = script_layer

    ai_layer = LayerScore('AI Prompt Detection', 0, 0.8, [])
    if (ai_results or {}).get('prompt_detected'):
        ai_layer.score = 5
        ai_layer.findings.append('Prompt de IA embebido (+5)')
    layers['ai'] = ai_layer

    # FIX BUG #3: score/nivel/indicadores finales delegados a
    # calculate_risk_score() (única fuente de verdad). Ya no se calcula
    # aquí una segunda fórmula ("suma acotada por confianza") que podía
    # divergir del score mostrado al usuario.
    final_score, level, indicators = calculate_risk_score(virus_results, script_results, ai_results)
    return final_score, level, indicators, layers




