import cbrkit
import argparse
import pprint
import random

from revisor_cve import RevisorCBR


def main(args):
    # leer datos
    base_de_casos = cargar_base_casos(args.base_casos)
    casos_a_resolver = cargar_base_casos(args.casos)

    # iniciar revisor
    revisor = RevisorCBR(base_de_casos,
                         num_casos_similares=args.num_similares,
                         taxonomia_cwe=args.cwe,
                         embeddings_cache_path=args.cache,
                         debug=args.debug)

    # procesar casos a resolver
    contador_exitos = 0
    contador_score_correctos = 0
    contador_av_correctos = 0

    ids_casos = list(casos_a_resolver.keys())
    total_casos = len(ids_casos)

    for id_caso in ids_casos:
        caso = casos_a_resolver[id_caso]
        # establecer un nuevo id del caso manualmente
        nuevo_id = 100000+id_caso
        caso_resuelto = revisor.ciclo_cbr(caso, id_caso=nuevo_id)
        if caso_resuelto['_meta']['exito']:
            contador_exitos = contador_exitos + 1
        
        if caso_resuelto['_meta']['score_correcto']:
            contador_score_correctos = contador_score_correctos + 1

        if caso_resuelto['_meta']['attackVector_correcto']:
            contador_av_correctos = contador_av_correctos + 1

        print("--- CASO RESUELTO ---")
        pprint.pprint(caso_resuelto, width=120)
        print("---------------------")

    print("\n========================================")
    print("         RESUMEN DE RESULTADOS          ")
    print("========================================")
    print(f"Total de casos procesados: {total_casos}")
    print("----------------------------------------")
    print(f"ACIERTO SCORE (Nivel Severidad): {contador_score_correctos} / {total_casos} ({100*contador_score_correctos/total_casos:.1f}%)")
    print(f"ACIERTO ATTACK VECTOR (Exacto) : {contador_av_correctos} / {total_casos} ({100*contador_av_correctos/total_casos:.1f}%)")
    print("----------------------------------------")
    print(f"ÉXITOS GLOBALES (Criterio Final): {contador_exitos} / {total_casos} ({100*contador_exitos/total_casos:.1f}%)")
    print("========================================")

    
def cargar_base_casos(path):
    return cbrkit.loaders.file(path)
 
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Ejemplo de uso del modelo CBR para valoración de vulnerabilidades CVE'
    )

    parser.add_argument('-b', '--base_casos',
                        type=str, default='datos/cve.base_casos.json',  required=False,
                        help='Path al fichero JSON/YAML con la base de casos' )
    parser.add_argument('-r', '--casos',
                        type=str, default='datos/cve.casos_a_resolver.json', required=False,
                        help='Path al fichero JSON/YAML con los casos a resolver',
                        )
    parser.add_argument('-c', '--cwe',
                        type=str, default='datos/jerarquia_cwe_1000.yaml', required=False,
                        help='Path al fichero YAML con la taxonomia CWE',
                        )
    parser.add_argument('-e', '--cache',
                        type=str, default='datos/embeddings_cache.db', required=False,
                        help='Path a la BD SQLite de caché de embeddings',
                        )
    parser.add_argument('-n', '--num_similares',
                        type=int, default=5, required=False,
                        help='Num. de casos similares a recuperar (k)')
    parser.add_argument('-d','--debug',
                        action='store_true', required=False, default=False,
                        help='Activar DEBUG de fases del ciclo CBR')

    args = parser.parse_args()
    main(args)