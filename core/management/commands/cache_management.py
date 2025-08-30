from django.core.management.base import BaseCommand
from django.core.cache import cache
from core.cache_service import CacheService
import redis
from django.conf import settings
import json

class Command(BaseCommand):
    help = 'Gerencia o cache Redis - limpar, monitorar, estatísticas'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['clear', 'stats', 'monitor', 'clear-pattern'],
            required=True,
            help='Ação a ser executada'
        )
        parser.add_argument(
            '--pattern',
            type=str,
            help='Padrão para limpar chaves específicas (usado com clear-pattern)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Saída detalhada'
        )
    
    def handle(self, *args, **options):
        action = options['action']
        verbose = options['verbose']
        
        if action == 'clear':
            self.clear_cache(verbose)
        elif action == 'stats':
            self.show_stats(verbose)
        elif action == 'monitor':
            self.monitor_cache(verbose)
        elif action == 'clear-pattern':
            pattern = options.get('pattern')
            if not pattern:
                self.stdout.write(
                    self.style.ERROR('Padrão é obrigatório para clear-pattern')
                )
                return
            self.clear_pattern(pattern, verbose)
    
    def clear_cache(self, verbose=False):
        """Limpa todo o cache"""
        try:
            if CacheService.clear_all():
                self.stdout.write(
                    self.style.SUCCESS('Cache limpo com sucesso!')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('Erro ao limpar cache')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Erro ao limpar cache: {e}')
            )
    
    def show_stats(self, verbose=False):
        """Mostra estatísticas do cache"""
        try:
            # Conecta diretamente ao Redis para estatísticas
            redis_url = getattr(settings, 'CACHES', {}).get('default', {}).get('LOCATION', 'redis://localhost:6379/1')
            r = redis.from_url(redis_url)
            
            info = r.info()
            
            self.stdout.write(self.style.SUCCESS('=== Estatísticas do Redis Cache ==='))
            self.stdout.write(f"Versão do Redis: {info.get('redis_version', 'N/A')}")
            self.stdout.write(f"Memória usada: {self._format_bytes(info.get('used_memory', 0))}")
            self.stdout.write(f"Memória máxima: {self._format_bytes(info.get('maxmemory', 0)) if info.get('maxmemory', 0) > 0 else 'Ilimitada'}")
            self.stdout.write(f"Chaves totais: {info.get('db1', {}).get('keys', 0) if 'db1' in info else 0}")
            self.stdout.write(f"Chaves expiradas: {info.get('expired_keys', 0)}")
            self.stdout.write(f"Cache hits: {info.get('keyspace_hits', 0)}")
            self.stdout.write(f"Cache misses: {info.get('keyspace_misses', 0)}")
            
            # Calcula hit rate
            hits = info.get('keyspace_hits', 0)
            misses = info.get('keyspace_misses', 0)
            total = hits + misses
            hit_rate = (hits / total * 100) if total > 0 else 0
            self.stdout.write(f"Hit rate: {hit_rate:.2f}%")
            
            if verbose:
                self.stdout.write("\n=== Informações Detalhadas ===")
                # Lista algumas chaves de exemplo
                keys = r.keys('*')[:10]  # Primeiras 10 chaves
                if keys:
                    self.stdout.write("Exemplos de chaves:")
                    for key in keys:
                        key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                        ttl = r.ttl(key)
                        ttl_str = f"{ttl}s" if ttl > 0 else "Sem expiração" if ttl == -1 else "Expirada"
                        self.stdout.write(f"  - {key_str} (TTL: {ttl_str})")
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Erro ao obter estatísticas: {e}')
            )
    
    def monitor_cache(self, verbose=False):
        """Monitora o cache em tempo real"""
        try:
            redis_url = getattr(settings, 'CACHES', {}).get('default', {}).get('LOCATION', 'redis://localhost:6379/1')
            r = redis.from_url(redis_url)
            
            self.stdout.write(self.style.SUCCESS('=== Monitor de Cache (Ctrl+C para sair) ==='))
            self.stdout.write("Monitorando comandos Redis...\n")
            
            # Inicia o monitor
            with r.monitor() as m:
                for command in m.listen():
                    if verbose or any(cmd in command['command'].lower() for cmd in ['get', 'set', 'del']):
                        timestamp = command['time']
                        cmd = command['command']
                        self.stdout.write(f"[{timestamp}] {cmd}")
                        
        except KeyboardInterrupt:
            self.stdout.write("\nMonitoramento interrompido.")
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Erro no monitoramento: {e}')
            )
    
    def clear_pattern(self, pattern, verbose=False):
        """Limpa chaves que correspondem ao padrão"""
        try:
            if CacheService.delete_pattern(pattern):
                self.stdout.write(
                    self.style.SUCCESS(f'Chaves com padrão "{pattern}" removidas com sucesso!')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'Erro ao remover chaves com padrão "{pattern}"')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Erro ao remover padrão: {e}')
            )
    
    def _format_bytes(self, bytes_value):
        """Formata bytes em unidades legíveis"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"