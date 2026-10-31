"""
Detector de texto generado por IA + detección de prompts/instrucciones
embebidas en archivos (útil para detectar payloads de prompt-injection
ocultos en scripts, documentos o comentarios).

Se degrada de forma segura si la librería opcional 'llmevalkit' no está
instalada, en vez de romper el arranque de la app.
"""

import re

try:
    from llmevalkit.detection import AITextDetector
    _LLMEVALKIT_AVAILABLE = True
except ImportError:
    _LLMEVALKIT_AVAILABLE = False


# Patrones típicos de instrucciones/prompts dirigidos a un modelo de lenguaje.
# Esto es detección basada en patrones (no decodifica ni ejecuta nada), pensada
# para señalar payloads de prompt-injection embebidos en archivos.
_PROMPT_INDICATOR_PATTERNS = [
    # N-19: 'you are a' / 'act as a' son frases de prosa normal ("you are a
    # hero", "act as a manager") y producían falsos positivos en documentos.
    # Solo se cuentan cuando el rol asignado es claramente un persona IA.
    r'\byou are (?:an?|the) (?:ai|a\.i\.|assistant|chatbot|model|gpt|llm|language\s+model|virtual\s+assistant)\b',
    r'\bact\s+as\s+(?:an?|the) (?:ai|a\.i\.|assistant|chatbot|model|gpt|llm|language\s+model|virtual\s+assistant)\b',
    r'ignore (?:all |any )?(?:previous|prior|above)\s+instructions',
    r'\bsystem\s*prompt\b',
    r'\bas an ai\b',
    r'<\|system\|>',
    r'\[INST\]',
    r'###\s*Instruction',
    r'\byou must (?:always|never)\b',
    r'\bdo not reveal\b',
    r'\bjailbreak\b',
    r'\bprompt\s*injection\b',
]
_PROMPT_INDICATOR_RE = [re.compile(p, re.IGNORECASE) for p in _PROMPT_INDICATOR_PATTERNS]


def detect_embedded_prompt(text):
    """Busca indicios de un prompt/instrucción para IA embebido en el texto."""
    if not text:
        return {'prompt_detected': False, 'indicator_count': 0}

    matched = sum(1 for pattern in _PROMPT_INDICATOR_RE if pattern.search(text))
    return {
        'prompt_detected': matched > 0,
        'indicator_count': matched,
    }


class AIDetector:
    def __init__(self):
        self.detector = AITextDetector() if _LLMEVALKIT_AVAILABLE else None

    def detect_ai_content(self, text):
        """Detecta si un texto fue generado por IA."""
        if not self.detector:
            return {
                'error': "llmevalkit no está instalado (pip install llmevalkit)",
                'ai_probability': None,
                'verdict': 'NO DISPONIBLE',
            }

        if not text.strip():
            return {'ai_probability': 0.0, 'verdict': 'SIN CONTENIDO', 'raw_score': None}

        result = self.detector.evaluate(answer=text)
        # score: 0.0 = probablemente IA, 1.0 = probablemente humano
        ai_probability = (1 - result.score) * 100

        if ai_probability > 70:
            verdict = 'GENERADO POR IA (Alta probabilidad)'
        elif ai_probability > 40:
            verdict = 'POSIBLE IA (Probabilidad media)'
        else:
            verdict = 'HUMANO (Probabilidad baja de IA)'

        return {
            'ai_probability': round(ai_probability, 2),
            'verdict': verdict,
            'raw_score': result.score,
        }

    def analyze_file(self, file_path):
        """Analiza el contenido de un archivo: probabilidad de IA + prompts embebidos."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Limitar a 10k caracteres
        except OSError as e:
            return {'error': f'No se pudo leer el archivo: {e}'}

        result = self.detect_ai_content(content)
        result.update(detect_embedded_prompt(content))
        return result

