"""
Traduce los resultados técnicos crudos (hashes, YARA, AST, heurística ML)
a resúmenes legibles para humanos:
  - classify_malware_type(): a partir del análisis de virus, infiere QUÉ TIPO
    de amenaza podría ser (packer, downloader, inyección de procesos, etc.)
  - describe_script_findings(): a partir del análisis de script, resume QUÉ
    HACE el script en frases simples en vez de listar cada regex.
Se usa tanto en la GUI (main.py) como en el reporte (report_generator.py),
para no duplicar esta lógica.
"""

from analysis_utils import is_high_entropy_expected


def classify_malware_type(virus_results):
    """Devuelve una lista de categorías de amenaza inferidas de los indicadores locales."""
    if not virus_results:
        return ['Sin datos de análisis']

    static = virus_results.get('static_analysis', {}) or {}
    suspicious = static.get('suspicious', []) or []
    yara = virus_results.get('yara', {}) or {}
    yara_matches = yara.get('matches', []) or []
    ml = virus_results.get('ml_prediction', {}) or {}
    reputation = virus_results.get('reputation', {}) or {}

    blob = ' '.join(suspicious).lower()
    blob += ' ' + ' '.join(m.get('rule', '') for m in yara_matches).lower()
    blob += ' ' + ' '.join(t for m in yara_matches for t in m.get('tags', [])).lower()
    blob += ' ' + ' '.join(str(v) for v in (static.get('meta') or {}).values()).lower()

    categories = set()

    if any(k in blob for k in ('upx', 'packed', 'empaquet', 'entropía alta', 'entropia alta')):
        categories.add('Empaquetado / Ofuscado (Packer)')

    if any(k in blob for k in ('createremotethread', 'writeprocessmemory', 'virtualallocex', 'virtualalloc')):
        categories.add('Inyección de código / Process Injection')

    if any(k in blob for k in ('internetopen', 'urldownload', 'socket', 'winhttp', 'ws2_32')):
        categories.add('Comunicación de red (posible Downloader/Backdoor)')

    if any(k in blob for k in ('createprocess', 'winexec', 'shellexecute')):
        categories.add('Ejecución de procesos (posible Dropper/Loader)')

    if 'tls callback' in blob or 'anti-análisis' in blob or 'anti-analisis' in blob:
        categories.add('Técnicas anti-análisis / anti-debugging')

    if 'no ejecutable' in blob:
        categories.add('Entry point sospechoso')

    if reputation.get('md5_match') or reputation.get('sha256_match'):
        categories.add('Coincide con hash de malware conocido (base de datos local)')

    if not categories and ml.get('prediction') in ('MALICIOUS', 'SOSPECHOSO'):
        categories.add('Comportamiento anómalo genérico (heurística/ML, sin firma específica)')

    # Strings embebidos (URLs/IPs) sugieren comunicación C2 potencial —
    # pero NO en contenedores donde URLs embebidas son parte normal del
    # formato (ej. x264 siempre firma sus MP4/MKV con la URL de VideoLAN;
    # metadatos EXIF de imágenes casi siempre traen URLs de fabricantes).
    strings_info = virus_results.get('strings', {})
    file_path = virus_results.get('file')
    strings_low_confidence = is_high_entropy_expected(file_path) if file_path else False

    if not strings_low_confidence:
        if strings_info.get('urls') or strings_info.get('ips'):
            categories.add('Contiene URLs/IPs embebidas (posible C2 o exfiltración)')
        if strings_info.get('suspicious_commands'):
            categories.add('Contiene referencias a PowerShell/cmd.exe embebidas')

    # Polyglot: técnica de evasión de filtros por extensión/formato
    if virus_results.get('polyglot'):
        categories.add('Archivo polyglot (múltiples formatos válidos) - técnica de evasión')

    # Señales de documentos ofimáticos / PDF (si el archivo era de ese tipo)
    doc = virus_results.get('document_analysis')
    if doc:
        if doc.get('has_macros') and doc.get('macro_keywords'):
            categories.add('Macro maliciosa (Office) - posible Dropper/Downloader')
        elif doc.get('has_macros'):
            categories.add('Documento con macros (sin palabras clave sospechosas conocidas)')
        if doc.get('type') == 'PDF' and doc.get('suspicious'):
            categories.add('PDF con JavaScript/acciones automáticas embebidas')

    # Señales de análisis dinámico (si se ejecutó explícitamente en sandbox)
    dynamic = virus_results.get('dynamic_analysis')
    if dynamic and dynamic.get('executed'):
        if dynamic.get('network_syscalls'):
            categories.add('Comportamiento de red observado en ejecución (sandbox)')
        if dynamic.get('files_accessed') and len(dynamic['files_accessed']) > 20:
            categories.add('Actividad de archivos intensa observada en ejecución (sandbox)')

    # Comportamiento simulado (dynamic_analyzer.py, 100% estático, sin ejecución)
    behavior = virus_results.get('behavior_analysis', {})
    if behavior and not behavior.get('low_confidence_container'):
        if behavior.get('network_indicators') and behavior.get('persistence_indicators'):
            categories.add('IOCs de red + persistencia embebidos (posible Downloader/Backdoor)')
        elif behavior.get('network_indicators'):
            categories.add('IOCs de red embebidos (posible comunicación C2)')
        elif behavior.get('persistence_indicators'):
            categories.add('IOCs de persistencia embebidos')
        if behavior.get('anti_analysis_indicators'):
            categories.add('Referencias anti-análisis/anti-VM embebidas')

    if not categories:
        return ['Sin indicadores de malware detectados']

    return sorted(categories)


_SCRIPT_CATEGORY_LABELS = {
    'obfuscation': 'ofuscación de código (eval/exec/base64)',
    'network': 'operaciones de red (requests/sockets)',
    'system': 'ejecución de comandos del sistema',
    'persistence': 'mecanismos de persistencia (tareas programadas, registro)',
    'encoding': 'codificación/decodificación de datos',
}


def describe_script_findings(script_results):
    """Resume en frases simples qué contiene un script analizado."""
    if not script_results:
        return ['Sin datos de análisis']

    if script_results.get('skipped'):
        return [script_results.get('reason', 'Archivo no analizado como script')]

    if script_results.get('error'):
        return [f"Error: {script_results['error']}"]

    findings = []
    for category, label in _SCRIPT_CATEGORY_LABELS.items():
        info = script_results.get(category, {})
        if info.get('count', 0) > 0:
            findings.append(f"Contiene {label} ({info['count']} coincidencia(s))")

    ast_info = script_results.get('ast_analysis', {})
    if ast_info.get('dynamic_exec'):
        findings.append(f"Ejecuta código dinámico con eval/exec/compile ({len(ast_info['dynamic_exec'])} veces)")
    if ast_info.get('network_ops', {}).get('urls'):
        findings.append(f"Contiene {len(ast_info['network_ops']['urls'])} URL(s) embebida(s)")
    if ast_info.get('network_ops', {}).get('ips'):
        findings.append(f"Contiene {len(ast_info['network_ops']['ips'])} dirección(es) IP embebida(s)")

    ps_info = script_results.get('powershell_analysis', {})
    if ps_info.get('suspicious'):
        findings.append(f"PowerShell con {len(ps_info['suspicious'])} cmdlet(s)/parámetro(s) sospechoso(s)")

    if not findings:
        findings.append('No se detectó contenido sospechoso en el script')

    return findings


def describe_document_findings(document_results):
    """Resume en frases simples los hallazgos de un documento (Office/PDF)."""
    if not document_results:
        return ['No aplica (no es un documento Office/PDF)']

    if document_results.get('error'):
        return [f"Error: {document_results['error']}"]

    findings = []
    doc_type = document_results.get('type')

    if doc_type == 'OFFICE':
        if document_results.get('has_macros'):
            findings.append('El documento contiene macros')
            if document_results.get('macro_keywords'):
                findings.append(f"Palabras clave sospechosas en la macro: {', '.join(document_results['macro_keywords'])}")
        else:
            findings.append('El documento no contiene macros')

    elif doc_type == 'PDF':
        if document_results.get('suspicious'):
            findings.extend(document_results['suspicious'])
        else:
            findings.append('No se detectaron marcadores sospechosos (JS, auto-ejecución, etc.)')

    if not findings:
        findings.append('Sin hallazgos relevantes')

    return findings


def describe_behavior_findings(behavior_results):
    """Resume en frases simples los IOCs del análisis de comportamiento
    (100% estático, ver dynamic_analyzer.py) — sin implicar ejecución."""
    if not behavior_results:
        return ['No disponible']

    if behavior_results.get('error'):
        return [f"Error: {behavior_results['error']}"]

    findings = []
    n_net = len(behavior_results.get('network_indicators', []))
    n_pers = len(behavior_results.get('persistence_indicators', []))
    n_anti = len(behavior_results.get('anti_analysis_indicators', []))
    n_fileops = len(behavior_results.get('file_op_indicators', []))
    n_imports = len(behavior_results.get('pe_imports', []))

    if n_net:
        findings.append(f"{n_net} indicador(es) de red embebido(s) (URLs/IPs/dominios)")
    if n_pers:
        findings.append(f"{n_pers} referencia(s) a mecanismos de persistencia")
    if n_anti:
        findings.append(f"{n_anti} referencia(s) anti-análisis/anti-VM")
    if n_fileops:
        findings.append(f"{n_fileops} referencia(s) a operaciones de archivo")
    if n_imports:
        findings.append(f"{n_imports} función(es) importada(s) en la tabla de imports (PE)")

    if not findings:
        findings.append('Sin IOCs de comportamiento detectados')

    return findings
