#!/usr/bin/env python3
"""
Entrena el modelo ML de MLDetector con muestras locales etiquetadas.

Estructura de carpetas esperada:
    samples/
        benign/       <- archivos legítimos (binarios propios, utilidades conocidas, etc.)
        malicious/    <- muestras de malware (¡SOLO en una VM aislada / entorno controlado!)

Datasets públicos etiquetados que puedes descargar tú mismo y adaptar a esta
estructura si quieres un modelo con más poder de generalización que unas
pocas muestras propias:
    - EMBER (Elastic):        https://github.com/elastic/ember
    - SOREL-20M (Sophos):     https://github.com/sophos/SOREL-20M
  (Ambos traen millones de muestras ya vectorizadas/etiquetadas; requieren
  su propio pipeline de descarga, son demasiado grandes para bajarlos aquí.)

Uso:
    python3 train_ml_model.py samples/ --output modelo_entrenado.skops

ADVERTENCIA: nunca ejecutes las muestras maliciosas, este script solo LEE
los bytes del archivo para extraer características estáticas (entropía,
tamaño, etc.), no las ejecuta en ningún momento.
"""

import argparse
import os
import sys

from ml_detector import MLDetector


def collect_samples(base_dir):
    samples, labels = [], []
    benign_dir = os.path.join(base_dir, 'benign')
    malicious_dir = os.path.join(base_dir, 'malicious')

    for d, label in ((benign_dir, 0), (malicious_dir, 1)):
        if not os.path.isdir(d):
            print(f"⚠️  No existe la carpeta esperada: {d}")
            continue
        for root, _dirs, files in os.walk(d):
            for fname in files:
                samples.append(os.path.join(root, fname))
                labels.append(label)

    return samples, labels


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('samples_dir', help="Carpeta con subcarpetas benign/ y malicious/")
    parser.add_argument('--output', default='ml_model.skops', help="Ruta .skops donde guardar el modelo entrenado")
    parser.add_argument('--min-samples', type=int, default=20,
                         help="Mínimo de muestras totales requeridas para entrenar (default: 20)")
    args = parser.parse_args()

    samples, labels = collect_samples(args.samples_dir)

    n_benign = labels.count(0)
    n_malicious = labels.count(1)
    print(f"Muestras benignas: {n_benign}")
    print(f"Muestras maliciosas: {n_malicious}")
    print(f"Total: {len(samples)}")

    if len(samples) < args.min_samples:
        print(f"\n❌ Se requieren al menos {args.min_samples} muestras totales para entrenar "
              f"un modelo mínimamente útil (tienes {len(samples)}).")
        print("   Con pocas muestras, el modelo memoriza en vez de generalizar.")
        print("   El heurístico integrado (sin modelo) sigue funcionando mientras tanto.")
        sys.exit(1)

    if n_benign == 0 or n_malicious == 0:
        print("\n❌ Se necesitan muestras de AMBAS clases (benign/ y malicious/) para entrenar.")
        sys.exit(1)

    if min(n_benign, n_malicious) < 2:
        print("\n❌ Se requieren al menos 2 muestras por clase para reservar una muestra de evaluación.")
        return 1

    try:
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        print(f"\n❌ No está disponible scikit-learn: {exc}", file=sys.stderr)
        return 1
    train_samples, test_samples, train_labels, test_labels = train_test_split(
        samples, labels, test_size=0.2, random_state=42, stratify=labels
    )

    detector = MLDetector()
    print(f"\nEntrenando con {len(train_samples)} muestras; reservadas para evaluación: {len(test_samples)}...")
    detector.train(train_samples, train_labels)
    correct = 0
    for sample, expected in zip(test_samples, test_labels):
        prediction = detector.predict(sample).get('prediction')
        correct += int(prediction == ('MALICIOUS' if expected == 1 else 'BENIGN'))
    print(f"Evaluación holdout: {correct}/{len(test_labels)} correctas ({correct / len(test_labels):.1%})")
    try:
        detector.save_model(args.output)
    except Exception as exc:
        print(f"\n❌ No se pudo guardar el modelo en '{args.output}': {exc}", file=sys.stderr)
        return 1

    print(f"\n✅ Modelo guardado en: {args.output}")
    print(f"   Actualiza config.json -> \"ml_model_path\": \"{args.output}\" para que la app lo use.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
