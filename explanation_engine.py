
"""
Motor de explicabilidad para detecciones de malware.
Proporciona justificaciones detalladas con mapeo a MITRE ATT&CK.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from risk_levels import LEVEL_RANK


class MITRETactic(Enum):
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    PRIVILEGE_ESCALATION = "TA0004"
    IMPACT = "TA0040"


@dataclass
class MITRETechnique:
    id: str
    name: str
    tactic: MITRETactic
    
    def __str__(self):
        return f"{self.id}: {self.name}"


TECHNIQUES = {
    'OBFUSCATED_FILES': MITRETechnique('T1027', 'Obfuscated Files or Information', MITRETactic.DEFENSE_EVASION),
    'SOFTWARE_PACKING': MITRETechnique('T1027.002', 'Software Packing', MITRETactic.DEFENSE_EVASION),
    'STRIPPED_PAYLOADS': MITRETechnique('T1027.008', 'Stripped Payloads', MITRETactic.DEFENSE_EVASION),
    'HIDE_ARTIFACTS': MITRETechnique('T1564', 'Hide Artifacts', MITRETactic.DEFENSE_EVASION),
    'COMMAND_OBFUSCATION': MITRETechnique('T1027.010', 'Command Obfuscation', MITRETactic.DEFENSE_EVASION),
    'REGISTRY_RUN': MITRETechnique('T1547.001', 'Registry Run Keys', MITRETactic.PERSISTENCE),
    'SCHEDULED_TASK': MITRETechnique('T1053', 'Scheduled Task/Job', MITRETactic.PERSISTENCE),
    'VIRTUAL_SANDBOX': MITRETechnique('T1497', 'Virtualization/Sandbox Evasion', MITRETactic.DEFENSE_EVASION),
    'SYSTEM_INFO': MITRETechnique('T1082', 'System Information Discovery', MITRETactic.DISCOVERY),
    'PHISHING': MITRETechnique('T1566', 'Phishing', MITRETactic.INITIAL_ACCESS),
    'DATA_ENCODING': MITRETechnique('T1132', 'Data Encoding', MITRETactic.COMMAND_AND_CONTROL),
    'PROCESS_INJECTION': MITRETechnique('T1055', 'Process Injection', MITRETactic.DEFENSE_EVASION),
}


@dataclass
class DetectionExplanation:
    indicator: str
    description: str
    location: str
    severity: str
    confidence: str
    mitre_technique: Optional[MITRETechnique] = None
    would_change_if: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)


class ExplanationEngine:
    def __init__(self):
        self.explanations: List[DetectionExplanation] = []
    
    def add_entropy_explanation(self, entropy: float, section: str, offset: str = "N/A") -> DetectionExplanation:
        if entropy > 7.8:
            desc = (f"Entropía de {entropy:.2f} indica contenido fuertemente "
                   f"ofuscado o cifrado en sección {section}.")
            technique = TECHNIQUES['OBFUSCATED_FILES']
            severity = "ALTA"
        elif entropy > 7.0:
            desc = f"Entropía elevada ({entropy:.2f}) sugiere posible empaquetado."
            technique = TECHNIQUES['SOFTWARE_PACKING']
            severity = "MEDIA"
        else:
            desc = f"Entropía normal ({entropy:.2f})"
            technique = None
            severity = "BAJA"
        
        exp = DetectionExplanation(
            indicator=f"Entropía_{section}",
            description=desc,
            location=f"Sección {section} (offset: {offset})",
            severity=severity,
            confidence="alta" if entropy > 7.5 else "media",
            mitre_technique=technique,
            would_change_if=[
                "Si el archivo estuviera firmado por Microsoft/Google, el riesgo bajaría a BAJO",
                "Si la sección fuera .rsrc en un ejecutable legítimo, podría ser normal"
            ],
            remediation=["Verificar firma digital", "Comparar con hash conocido"]
        )
        self.explanations.append(exp)
        return exp
    
    def add_overlay_explanation(self, size: int, entropy: float, offset: int) -> DetectionExplanation:
        desc = f"Datos adjuntos de {size:,} bytes al final del ejecutable (overlay)."
        if entropy > 7.0:
            desc += " Alta entropía sugiere contenido cifrado."
            technique = TECHNIQUES['STRIPPED_PAYLOADS']
            severity = "ALTA"
        else:
            technique = TECHNIQUES['HIDE_ARTIFACTS']
            severity = "MEDIA"
        
        exp = DetectionExplanation(
            indicator="PE_Overlay",
            description=desc,
            location=f"Offset {offset}+",
            severity=severity,
            confidence="alta",
            mitre_technique=technique,
            would_change_if=[
                "Si el overlay fuera un certificado digital válido, sería normal",
                "Si contiene recursos legítimos (iconos), ajustar a BAJO"
            ],
            remediation=["Extraer overlay para análisis adicional"]
        )
        self.explanations.append(exp)
        return exp
    
    def add_packer_explanation(self, packer_name: str, section: str = ".text") -> DetectionExplanation:
        exp = DetectionExplanation(
            indicator=f"Packer_{packer_name}",
            description=f"Detectado empaquetador {packer_name}. Comprime/encripta el código real.",
            location=section,
            severity="ALTA",
            confidence="alta",
            mitre_technique=TECHNIQUES['SOFTWARE_PACKING'],
            would_change_if=[
                "Si el packer es UPX y el archivo está firmado, podría ser legítimo",
                "Verificar hash en whitelist de software conocido"
            ],
            remediation=["Desempaquetar para análisis estático profundo"]
        )
        self.explanations.append(exp)
        return exp

    def add_similarity_explanation(self, fuzzy_method: str,
                                   match_value: str = "",
                                   location: str = "Hash fuzzy") -> DetectionExplanation:
        """N-19 residual: la similitud fuzzy (TLSH/ssdeep) contra una muestra
        de malware NO es 'Software Packing'. Antes se reutilizaba
        add_packer_explanation(), que asignaba MITRE T1027.002 (técnica
        incorrecta). Aquí se explica como evidencia de similitud de contenido,
        sin técnica MITRE (no es una técnica de evasión identificable)."""
        detail = f" ({match_value})" if match_value else ""
        exp = DetectionExplanation(
            indicator=f"Fuzzy_{fuzzy_method}",
            description=(f"Similitud fuzzy {fuzzy_method.upper()} con una muestra de "
                         f"malware conocida{detail}. No es hash exacto, sino "
                         f"contenido estructuralmente parecido."),
            location=location,
            severity="ALTA",
            confidence="media",
            mitre_technique=None,
            would_change_if=[
                "Si la distancia TLSH/ssdeep es alta, puede ser coincidencia en librerías comunes",
                "Si el archivo está firmado por un vendor legítimo, revisar como FP"
            ],
            remediation=[
                "Comparar manualmente con la muestra parecida",
                "Contrastar con más reglas YARA antes de concluir"
            ]
        )
        self.explanations.append(exp)
        return exp
    
    def add_imphash_explanation(self, imphash: str, matches: int) -> DetectionExplanation:
        exp = DetectionExplanation(
            indicator=f"Imphash_{imphash[:16]}...",
            description=f"Hash de imports coincide con {matches} muestras de malware conocido.",
            location="Tabla de imports PE",
            severity="ALTA",
            confidence="muy alta",
            mitre_technique=None,
            would_change_if=[
                "Si el archivo está firmado por el vendor original, podría ser FP",
                "Verificar contra NSRL si es software de sistema"
            ],
            remediation=["Buscar muestras relacionadas por imphash"]
        )
        self.explanations.append(exp)
        return exp
    
    def add_archive_password_explanation(self) -> DetectionExplanation:
        exp = DetectionExplanation(
            indicator="Archive_Password_Protected",
            description="Archivo protegido con contraseña. Técnica común en phishing para evadir escaneo.",
            location="Archivo comprimido",
            severity="MEDIA",
            confidence="media",
            mitre_technique=TECHNIQUES['PHISHING'],
            would_change_if=[
                "Si el archivo fue recibido de fuente confiable conocida",
                "Si se conoce la contraseña y el contenido es legítimo"
            ],
            remediation=["No abrir archivos protegidos de fuentes desconocidas"]
        )
        self.explanations.append(exp)
        return exp
    
    def add_hash_match_explanation(self, hash_type: str, hash_value: str = "") -> DetectionExplanation:
        """FIX BUG #2: antes no existía ningún add_*_explanation() para un
        match de hash contra la base de malware conocido (HASH_KNOWN_BAD),
        así que ese indicador -pese a producir un score de 100/CRÍTICO en
        calculate_risk_score()- nunca dejaba rastro en self.explanations,
        y generate_summary() caía en el mensaje por defecto ("El archivo
        parece limpio")."""
        short_hash = f" ({hash_value[:16]}...)" if hash_value else ""
        exp = DetectionExplanation(
            indicator=f"Hash_{hash_type}_Match",
            description=(f"El hash {hash_type.upper()}{short_hash} del archivo coincide "
                         f"EXACTAMENTE con una muestra de malware conocida en la base de firmas."),
            location="Hash completo del archivo",
            severity="ALTA",
            confidence="muy alta",
            mitre_technique=None,
            would_change_if=[
                "Nunca: un match exacto de hash contra una base de malware confirmada "
                "es una certeza, no una heurística que pueda revertirse por contexto."
            ],
            remediation=["No ejecutar ni distribuir el archivo", "Aislar en cuarentena de inmediato",
                        "Reportar el hallazgo (hash, origen) al equipo de seguridad"]
        )
        self.explanations.append(exp)
        return exp

    def add_yara_explanation(self, rule_name: str, severity_level: str = 'medium') -> DetectionExplanation:
        """FIX BUG #2: igual que con el hash match, un match de YARA no
        generaba ninguna DetectionExplanation, así que quedaba fuera del
        resumen 'Explainable AI' aunque sí sumara al risk_score."""
        sev_map = {'high': 'ALTA', 'medium': 'MEDIA', 'low': 'BAJA'}
        severity = sev_map.get(severity_level, 'MEDIA')
        exp = DetectionExplanation(
            indicator=f"YARA_{rule_name}",
            description=(f"El archivo coincide con la regla YARA '{rule_name}', que codifica "
                         f"un patrón conocido de malware o comportamiento sospechoso."),
            location="Contenido del archivo (patrón YARA)",
            severity=severity,
            confidence="alta",
            mitre_technique=None,
            would_change_if=[
                "Si la regla es genérica y coincide también con software legítimo "
                "empaquetado de forma similar (falso positivo conocido de esa regla)"
            ],
            remediation=["Revisar la regla YARA que disparó la coincidencia",
                        "Analizar el archivo en un entorno aislado antes de confiar en él"]
        )
        self.explanations.append(exp)
        return exp

    def add_anti_analysis_explanation(self, technique_name: str) -> DetectionExplanation:
        exp = DetectionExplanation(
            indicator=f"AntiAnalysis_{technique_name}",
            description=f"Referencia a '{technique_name}' indica detección de análisis dinámico.",
            location="Tabla de imports / Strings",
            severity="MEDIA",
            confidence="media",
            mitre_technique=TECHNIQUES['VIRTUAL_SANDBOX'],
            would_change_if=[
                "Algunos software legítimos usan anti-debugging para protección DRM",
                "Verificar si pertenece a software de seguridad conocido"
            ],
            remediation=["Ejecutar en sandbox aislada si se requiere análisis dinámico"]
        )
        self.explanations.append(exp)
        return exp
    
    def generate_summary(self, risk_level: Optional[str] = None,
                          risk_indicators: Optional[List[str]] = None) -> Dict[str, Any]:
        """Genera el resumen "Explainable AI".

        FIX BUG #2 (CRÍTICO): antes este resumen -y sus 'recommendations',
        el texto que un operador humano lee primero- se derivaba
        ÚNICAMENTE de las DetectionExplanation registradas vía los métodos
        add_*_explanation(). Esos métodos no cubrían todos los indicadores
        que calculate_risk_score() sí puntúa (p.ej. HASH_KNOWN_BAD antes de
        este fix, o cualquier indicador futuro para el que no exista un
        add_*_explanation() dedicado). Resultado observado en producción:
        un archivo con hash malicioso conocido (score=100, CRÍTICO)
        mostraba "No se detectaron indicadores significativos" /
        "El archivo parece limpio" en el resumen — contradiciendo el score
        mostrado en la misma pantalla.

        Ahora el llamador (cli.py, main.py) pasa el risk_level/indicators
        YA calculados por calculate_risk_score() -única fuente de verdad
        del score numérico- y esta función los usa como piso: el
        'risk_level' devuelto aquí NUNCA es menor al real, y si hay
        indicadores del motor de scoring sin una DetectionExplanation
        asociada, igual se reflejan en el resumen y las recomendaciones
        en vez de mostrar el mensaje por defecto de "archivo limpio".
        """
        risk_indicators = risk_indicators or []

        if not self.explanations:
            if risk_indicators:
                level = risk_level or 'BAJO'
                return {
                    'summary': (f"{len(risk_indicators)} indicador(es) detectado(s) por el motor "
                               f"de scoring: {', '.join(risk_indicators[:8])}"),
                    'risk_level': level,
                    'techniques': [],
                    'mitre_techniques': [],
                    'high_risk_indicators': [],
                    'recommendations': _recommendations_for_level(level),
                    'detailed_explanations': [],
                }
            return {
                'summary': 'No se detectaron indicadores significativos',
                'risk_level': risk_level or 'BAJO',
                'techniques': [],
                'mitre_techniques': [],
                'high_risk_indicators': [],
                'detailed_explanations': [],
                'recommendations': _recommendations_for_level(risk_level) if risk_level else ['El archivo parece limpio']
            }

        high = [e for e in self.explanations if e.severity == 'ALTA']
        medium = [e for e in self.explanations if e.severity == 'MEDIA']

        if len(high) >= 2:
            derived_risk = 'CRÍTICO'
        elif high:
            derived_risk = 'ALTO'
        elif len(medium) >= 3:
            derived_risk = 'MEDIO'
        elif medium:
            derived_risk = 'MEDIO'
        else:
            derived_risk = 'BAJO'

        # N-09(d): calculate_risk_score() es la ÚNICA fuente de verdad del
        # nivel. Antes se mostraba el máximo con el nivel derivado de las
        # explicaciones, de modo que un archivo en whitelist (score BAJO) podía
        # aparecer como CRÍTICO. El nivel derivado se conserva aparte como
        # 'signals_level' (informativo).
        final_risk = risk_level if risk_level else derived_risk

        recs = []
        techniques = []

        for exp in self.explanations:
            if exp.mitre_technique:
                techniques.append(str(exp.mitre_technique))
            recs.extend(exp.remediation)

        explained_indicators = {e.indicator for e in self.explanations}
        extra_indicators = [i for i in risk_indicators if i not in explained_indicators]

        summary_text = f"{len(high)} indicadores de alto riesgo, {len(medium)} de riesgo medio"
        if extra_indicators:
            summary_text += f" (+ {len(extra_indicators)} indicador(es) adicional(es) del motor de scoring: " \
                             f"{', '.join(extra_indicators[:5])})"
            recs.extend(_recommendations_for_level(final_risk))

        return {
            'summary': summary_text,
            'risk_level': final_risk,
            'signals_level': derived_risk,
            'techniques': sorted(set(techniques)),
            'high_risk_indicators': [e.indicator for e in high],
            'mitre_techniques': sorted(set(techniques)),
            # orden determinista (A-8) conservando el de aparición
            'recommendations': list(dict.fromkeys(recs)),
            'detailed_explanations': [
                {
                    'indicator': e.indicator,
                    'description': e.description,
                    'location': e.location,
                    'severity': e.severity,
                    'mitre': str(e.mitre_technique) if e.mitre_technique else None,
                    'would_change_if': e.would_change_if
                }
                for e in self.explanations
            ]
        }


_LEVEL_RANK = LEVEL_RANK  # K4: fuente única en risk_levels.py

_GENERIC_RECOMMENDATIONS = {
    'CRÍTICO': ["No ejecutar ni distribuir el archivo", "Aislar/poner en cuarentena de inmediato",
                "Investigar el origen del archivo"],
    'ALTO': ["Tratar el archivo como potencialmente malicioso",
             "Analizar en un entorno aislado (sandbox) antes de usarlo"],
    'MEDIO': ["Verificar el origen del archivo antes de usarlo",
              "Revisar manualmente los indicadores reportados"],
    'BAJO': ["Revisar el archivo si proviene de una fuente no confiable"],
    'SIN RIESGO DETECTADO': ["El archivo parece limpio"],
}


def _recommendations_for_level(level: Optional[str]) -> List[str]:
    return list(_GENERIC_RECOMMENDATIONS.get(level or 'BAJO', _GENERIC_RECOMMENDATIONS['BAJO']))


def _max_level(a: Optional[str], b: Optional[str]) -> str:
    """Devuelve el nivel de riesgo más severo entre a y b (b puede ser None)."""
    if not b:
        return a or 'BAJO'
    if not a:
        return b
    return a if _LEVEL_RANK.get(a, 0) >= _LEVEL_RANK.get(b, 0) else b
