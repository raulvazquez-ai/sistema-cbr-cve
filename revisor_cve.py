from core import CBR, CBR_DEBUG
import cbrkit
import numpy as np
from collections import Counter

class RevisorCBR(CBR):
    
    #niveles de severidad
    def _get_severity_level(self, score):
        if score == 0.0: return "None"
        elif 0.1 <= score <= 3.9: return "Low"
        elif 4.0 <= score <= 6.9: return "Medium"
        elif 7.0 <= score <= 8.9: return "High"
        elif 9.0 <= score <= 10.0: return "Critical"
        return "Unknown"

    #aplicar un número a los niveles de severidad
    def _get_severity_numeric_level(self, score):
        level = self._get_severity_level(score)
        mapping = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4, "Unknown": -1}
        return mapping.get(level, -1)

    #calcular los niveles de severidad adyacentes
    def _are_severity_levels_adjacent(self, score1, score2):
        level1_num = self._get_severity_numeric_level(score1)
        level2_num = self._get_severity_numeric_level(score2)
        if level1_num == -1 or level2_num == -1: return False
        return abs(level1_num - level2_num) == 1

    def __init__(self, base_de_casos, 
                       num_casos_similares, 
                       taxonomia_cwe,
                       embeddings_cache_path,
                       usar_keywords=False,  
                       debug=False):
        
        super().__init__(base_de_casos, num_casos_similares)
        if debug:
            self.DEBUG = CBR_DEBUG(self.prettyprint_caso)
        else: 
            self.DEBUG = None

        self.retriever = self.inicializar_retriever(num_casos_similares, taxonomia_cwe, embeddings_cache_path, usar_keywords)    
        
    def inicializar_retriever(self, num_casos_similares, 
                              taxonomia_cwe, 
                              embeddings_cache_path,
                              usar_keywords): 

        #similaridad cadena escalar
        assigner_similarity = cbrkit.sim.generic.equality()

        #similaridad lista de cadenas escalares
        products_similarity = cbrkit.sim.collections.isolated_mapping(element_similarity=cbrkit.sim.strings.levenshtein())

        #similaridad cadena escalar tomada de una jerarquía de conceptos -> jerarquia_cwe_1000.yaml
        cwe_similarity = cbrkit.sim.taxonomy.build(taxonomia_cwe, 
                                                    cbrkit.sim.taxonomy.wu_palmer())

        #si se quiere hacer la similaridad sin cache descomentar embedding_sin_cache y similaridad_sin_cache y comentar embedding_con_cache
        #y similaridad_con_cache.

        """
        embedding_sin_cache = cbrkit.sim.embed.sentence_transformers(model="all-MiniLM-L6-v2")
        """

        embedding_con_cache = cbrkit.sim.embed.cache(
            func=cbrkit.sim.embed.sentence_transformers(model="all-MiniLM-L6-v2"),
            path=embeddings_cache_path,
            table="vectores"
        )
            
        """
        similaridad_sin_cache = cbrkit.sim.embed.build(
            conversion_func=embedding_sin_cache, 
            sim_func=cbrkit.sim.embed.cosine()
        )
        """

        similaridad_con_cache = cbrkit.sim.embed.build(
            conversion_func=embedding_con_cache,
            sim_func=cbrkit.sim.embed.cosine()
        )
        
        #similaridad lista palabras clave
        keywords_similarity = cbrkit.sim.collections.jaccard()
       
        #Funcion de similaridad
        #se está utilizando description. si se quiere utilizar keywords descomentar las líneas de keywords y comentar description.

        case_similarity = cbrkit.sim.attribute_value(
                            attributes={
                                "assigner": assigner_similarity,
                                "affected_products": products_similarity,
                                "cwe": cwe_similarity,
                                #"keywords": keywords_similarity,
                                "description": similaridad_con_cache #sin cache -> cambiar similaridad_con_cache a similaridad_sin_cache
                                },
                            aggregator=cbrkit.sim.aggregator(
                                pooling="mean",
                                pooling_weights={
                                    "cwe": 0.3,
                                    "affected_products": 0.2,
                                    "assigner": 0.1,
                                    #"keywords": 0.5,
                                    "description": 0.4
                                }
                            ),
                        )
        
        #creacion del retriever
        retriever = cbrkit.retrieval.build(case_similarity)
        filtro_limite = cbrkit.retrieval.dropout(retriever, limit=num_casos_similares)
        return filtro_limite
        
    def prettyprint_caso(self, caso, meta = None):
        if (meta is None) and '_meta' in caso:
            meta = caso['_meta']
        
        metric = caso.get('metric', {})
        prettyprint_caso = "ID: {}, Score: {:.1f}, AV: {}".format(
            caso.get('id', 'N/A'),
            metric.get('score', 0.0),
            metric.get('attackVector', 'N/A')
        )
        
        if meta is not None:
            pretty_print_meta = (
                "[META: id: {}, score_real: {:.1f}, score_pred: {:.1f}, "
                "av_real: {}, av_pred: {}, exito: {}, corregido: {}]"
            ).format(
                meta.get('id', 'N/A'),
                meta.get('score_real', 0.0), meta.get('score_predicho', 0.0),
                meta.get('attackVector_real', 'N/A'), meta.get('attackVector_predicho', 'N/A'),
                meta.get('exito', False), meta.get('corregido', False)
            )
            prettyprint_caso = prettyprint_caso + " -> " + pretty_print_meta
    
        return prettyprint_caso
    
    def inicializar_caso(self, caso, id = None):
        #inicializar atributo _meta, anotando id si lo hay
        super().inicializar_caso(caso, id)

        #inicializar metadatos del caso para el problema de revisión
        metric_real = caso.get('metric', {})
        caso['_meta']['score_real'] = metric_real.get('score', 0.0)
        caso['_meta']['attackVector_real'] = metric_real.get('attackVector', 'UNKNOWN')

        caso['_meta']['score_predicho'] = 0.0
        caso['_meta']['attackVector_predicho'] = 'UNKNOWN'
        caso['_meta']['exito'] = False
        caso['_meta']['corregido'] = False
        caso['_meta']['score_correcto'] = False
        caso['_meta']['attackVector_correcto'] = False

        return caso

        
    def recuperar(self, caso_a_resolver):
        result = cbrkit.retrieval.apply_query(self.base_de_casos, caso_a_resolver, self.retriever)
        casos_similares = []
        similaridades = []
        for i in result.ranking:
            casos_similares.append(self.base_de_casos[i])
            similaridades.append(result.similarities[i].value)

        #DEBUG
        if self.DEBUG : self.DEBUG.debug_recuperar(caso_a_resolver, casos_similares, similaridades)

        return (casos_similares, similaridades)
    
    
    def reutilizar(self, caso_a_resolver, casos_similares, similaridades):
        if not casos_similares:
            caso_resuelto = dict(caso_a_resolver)
            caso_resuelto.setdefault('metric', {})['score'] = 0.0
            caso_resuelto.setdefault('metric', {})['attackVector'] = 'UNKNOWN'
            caso_resuelto['_meta']['score_predicho'] = 0.0
            caso_resuelto['_meta']['attackVector_predicho'] = 'UNKNOWN'
            
            #DEBUG
            if self.DEBUG: self.DEBUG.debug_reutilizar(caso_resuelto)
            return caso_resuelto
        
        scores_similares = [c.get('metric', {}).get('score', 0.0) for c in casos_similares]
        pesos = np.array(similaridades)
        
        #predicción del score utilizando la media ponderada
        if pesos.sum() == 0:
            score_predicho = float(np.mean(scores_similares))
        else:
            score_predicho = float(np.average(scores_similares, weights=pesos))

        vectors_similares = [
            c.get('metric', {}).get('attackVector', 'UNKNOWN') for c in casos_similares
        ]

        vectors_validos = [v for v in vectors_similares if v != 'UNKNOWN']
        if not vectors_validos:
            attackVector_predicho = 'UNKNOWN'
        else:
            counts = Counter(vectors_validos)
            #predicción de attackVector utilizando el valor más repetido (moda)
            attackVector_predicho = counts.most_common(1)[0][0]

        caso_resuelto = dict(caso_a_resolver)
        caso_resuelto.setdefault('metric', {})

        caso_resuelto['metric']['score'] = score_predicho
        caso_resuelto['metric']['attackVector'] = attackVector_predicho
        caso_resuelto['_meta']['score_predicho'] = score_predicho
        caso_resuelto['_meta']['attackVector_predicho'] = attackVector_predicho

        #DEBUG
        if self.DEBUG : self.DEBUG.debug_reutilizar(caso_resuelto)
        
        return caso_resuelto
        
        
    def revisar(self, caso_resuelto, caso_a_resolver=None, casos_similares=None, similaridades=None):
        meta = caso_resuelto['_meta']
        score_real = meta['score_real']
        score_predicho = meta['score_predicho']
        attackVector_real = meta['attackVector_real']
        attackVector_predicho = meta['attackVector_predicho']

        if score_real == 0.0 and attackVector_real == 'UNKNOWN':
            #DEBUG
            if self.DEBUG: self.DEBUG.debug_revisar(caso_resuelto, es_exito=False, es_corregido=False)
            return dict(caso_resuelto)

        score_level_real = self._get_severity_level(score_real)
        score_level_pred = self._get_severity_level(score_predicho)
        #predicción correcta -> valor predicho y valor real entran en el mismo nivel de severidad
        score_correcto = (score_level_real == score_level_pred)

        #predicción correcta -> valor predicho y valor real son iguales
        attackVector_correcto = (attackVector_real == attackVector_predicho)

        exito = False
        if score_correcto:
            #caso de éxito -> predicción de score correcta
            exito = True
        elif attackVector_correcto and self._are_severity_levels_adjacent(score_real, score_predicho):
            #caso de éxito -> predicción de attackVector correcta y asignación al score de un valor en un nivel de severidad adyacente al correcto
            exito = True

        caso_revisado = dict(caso_resuelto)
        caso_revisado['_meta']['exito'] = exito
        caso_revisado['_meta']['score_correcto'] = score_correcto
        caso_revisado['_meta']['attackVector_correcto'] = attackVector_correcto

        corregido = False
        if not score_correcto:
            #predicción de score incorrecta -> asignación del valor real
            caso_revisado['metric']['score'] = score_real
            corregido = True
        
        if not attackVector_correcto:
            #predicción de attackVector incorrecta -> asignación del valor real
            caso_revisado['metric']['attackVector'] = attackVector_real
            corregido = True

        caso_revisado['_meta']['corregido'] = corregido
   
        #DEBUG
        if self.DEBUG : self.DEBUG.debug_revisar(caso_revisado,
                                               es_exito=exito,
                                               es_corregido=corregido)
        
        return caso_revisado


    def retener(self, caso_revisado, caso_a_resolver=None, casos_similares=None, similaridades=None):
        es_retenido = False
        meta = caso_revisado['_meta']

        #caso retenido -> caso en el que se hayan corregido alguno de los atributos a predecir
        if meta['corregido']:
            self.base_de_casos[meta['id']] = caso_revisado
            es_retenido = True

        # caso retenido -> casos de éxito en los que se hayan predicho correctamente ambos atributos
        elif meta['exito'] and meta['score_correcto'] and meta['attackVector_correcto']:
            self.base_de_casos[meta['id']] = caso_revisado
            es_retenido = True
  
        #DEBUG
        if self.DEBUG : self.DEBUG.debug_retener(caso_revisado, es_retenido=es_retenido)