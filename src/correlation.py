import logging
from datetime import datetime, timedelta
from geopy.distance import geodesic
import pandas as pd
from collections import defaultdict
import re
from llm_client import OllamaClient
from dateutil.parser import parse as parse_date

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self.max_distance_km = config.MAX_CORRELATION_DISTANCE_KM
        self.time_window_hours = config.CORRELATION_TIME_WINDOW_HOURS
        self.llm_client = OllamaClient(config) if config.OLLAMA_ENABLE else None
        
    def correlate_forensic_osint(self, forensic_events, osint_data, location=None):
        correlations = []
        
        logger.info(f"Correlating {len(forensic_events)} forensic events with {len(osint_data)} OSINT items")
        
        for forensic_event in forensic_events:
            event_correlations = self._find_temporal_correlations(
                forensic_event, osint_data, location
            )
            
            if event_correlations:
                correlations.append({
                    'forensic_event': forensic_event,
                    'osint_correlations': event_correlations,
                    'correlation_strength': self._calculate_correlation_strength(
                        forensic_event, event_correlations
                    )
                })
        
        correlations.sort(key=lambda x: x['correlation_strength'], reverse=True)
        logger.info(f"Found {len(correlations)} correlations")
        
        return correlations
    
    def _find_temporal_correlations(self, forensic_event, osint_data, location=None):
        correlations = []
        forensic_time = self._ensure_datetime(forensic_event['timestamp'])
        
        time_window = timedelta(hours=self.time_window_hours)
        start_window = forensic_time - time_window
        end_window = forensic_time + time_window
        
        for osint_item in osint_data:
            osint_time = self._ensure_datetime(osint_item['timestamp'])
            
            if start_window <= osint_time <= end_window:
                time_diff_hours = abs((forensic_time - osint_time).total_seconds()) / 3600
                
                correlation = {
                    'osint_item': osint_item,
                    'temporal_proximity': time_diff_hours,
                    'spatial_proximity': None,
                    'content_relevance': 0.0
                }
                
                if location and osint_item.get('coordinates'):
                    correlation['spatial_proximity'] = self._calculate_spatial_proximity(
                        location, osint_item['coordinates']
                    )
                
                correlation['content_relevance'] = self._calculate_content_relevance(
                    forensic_event, osint_item
                )
                
                correlations.append(correlation)
        
        correlations.sort(key=lambda x: x['temporal_proximity'])
        return correlations
    
    def _ensure_datetime(self, timestamp):
        """Ensure timestamp is a datetime object, converting from string if necessary"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                return parse_date(timestamp)
            except Exception as e:
                logger.warning(f"Failed to parse timestamp '{timestamp}': {e}")
                # just use now if parsing fails
                return datetime.now()
        else:
            logger.warning(f"Invalid timestamp type: {type(timestamp)}")
            return datetime.now()
    
    def _calculate_spatial_proximity(self, location, coordinates):
        try:
            if isinstance(location, dict) and 'lat' in location and 'lon' in location:
                location_coords = (location['lat'], location['lon'])
            else:
                return None
                
            osint_coords = (coordinates['lat'], coordinates['lon'])
            distance_km = geodesic(location_coords, osint_coords).kilometers
            
            return {
                'distance_km': distance_km,
                'within_threshold': distance_km <= self.max_distance_km
            }
            
        except Exception as e:
            logger.debug(f"Error calculating spatial proximity: {e}")
            return None
    
    def _calculate_content_relevance(self, forensic_event, osint_item):
        # see if the LLM can help us figure out relevance
        if self.llm_client and self.llm_client.is_available():
            try:
                llm_analysis = self.llm_client.analyze_correlation_relevance(forensic_event, osint_item.get('content', ''))
                if llm_analysis and 'correlation_score' in llm_analysis:
                    llm_score = llm_analysis['correlation_score'] / 10.0  # normalize to 0-1
                    
                    # save this analysis so we can use it later
                    if 'llm_analysis' not in osint_item:
                        osint_item['llm_analysis'] = llm_analysis
                    
                    # blend LLM insights with old school methods
                    traditional_score = self._calculate_traditional_relevance(forensic_event, osint_item)
                    
                    # trust the LLM more but don't ignore the basics
                    combined_score = (llm_score * 0.7) + (traditional_score * 0.3)
                    return min(combined_score, 1.0)
            except Exception as e:
                logger.debug(f"LLM correlation analysis failed: {e}")
        
        # if LLM isn't available, do it the old way
        return self._calculate_traditional_relevance(forensic_event, osint_item)
    
    def _calculate_traditional_relevance(self, forensic_event, osint_item):
        # good old fashioned text matching
        relevance_score = 0.0
        
        forensic_path = forensic_event.get('file_path', '').lower()
        osint_content = osint_item.get('content', '').lower()
        
        filename = forensic_path.split('/')[-1] if forensic_path else ''
        
        if filename and len(filename) > 3:
            if filename in osint_content:
                relevance_score += 0.8
        
        path_keywords = self._extract_path_keywords(forensic_path)
        content_keywords = self._extract_content_keywords(osint_content)
        
        common_keywords = set(path_keywords) & set(content_keywords)
        if common_keywords:
            relevance_score += min(0.6, len(common_keywords) * 0.1)
        
        security_keywords = {
            'malware', 'virus', 'trojan', 'hack', 'breach', 'compromise', 
            'attack', 'exploit', 'vulnerability', 'threat', 'incident'
        }
        
        if any(keyword in osint_content for keyword in security_keywords):
            if any(indicator in forensic_path for indicator in [
                'temp', 'cache', 'download', 'appdata', 'roaming', 'system32'
            ]):
                relevance_score += 0.4
        
        file_extensions = {'.exe', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.dll'}
        if any(ext in forensic_path for ext in file_extensions):
            if any(keyword in osint_content for keyword in ['software', 'program', 'application', 'tool']):
                relevance_score += 0.3
        
        return min(relevance_score, 1.0)
    
    def _extract_path_keywords(self, file_path):
        keywords = []
        
        path_parts = re.split(r'[/\\]', file_path)
        for part in path_parts:
            if len(part) > 2:
                words = re.findall(r'\b[a-zA-Z]+\b', part.lower())
                keywords.extend(word for word in words if len(word) > 3)
        
        return list(set(keywords))
    
    def _extract_content_keywords(self, content):
        words = re.findall(r'\b[a-zA-Z]+\b', content.lower())
        
        stop_words = {
            'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 
            'by', 'is', 'are', 'was', 'were', 'been', 'have', 'has', 'had', 'will',
            'would', 'could', 'should', 'this', 'that', 'these', 'those', 'from'
        }
        
        return list(set(word for word in words if len(word) > 3 and word not in stop_words))
    
    def _calculate_correlation_strength(self, forensic_event, correlations):
        if not correlations:
            return 0.0
            
        strength = 0.0
        
        for correlation in correlations:
            temporal_score = max(0, 1 - (correlation['temporal_proximity'] / self.time_window_hours))
            
            spatial_score = 0.5
            if correlation['spatial_proximity'] and correlation['spatial_proximity']['within_threshold']:
                distance_ratio = correlation['spatial_proximity']['distance_km'] / self.max_distance_km
                spatial_score = max(0, 1 - distance_ratio)
            
            content_score = correlation['content_relevance']
            
            correlation_score = (temporal_score * 0.4) + (spatial_score * 0.3) + (content_score * 0.3)
            strength = max(strength, correlation_score)
        
        return strength
    
    def generate_timeline_analysis(self, correlations):
        timeline = []
        
        for correlation in correlations:
            forensic_event = correlation['forensic_event']
            
            timeline_entry = {
                'timestamp': forensic_event['timestamp'],
                'type': 'forensic',
                'event': forensic_event,
                'correlations': len(correlation['osint_correlations']),
                'strength': correlation['correlation_strength']
            }
            timeline.append(timeline_entry)
            
            for osint_corr in correlation['osint_correlations'][:3]:
                osint_item = osint_corr['osint_item']
                timeline_entry = {
                    'timestamp': osint_item['timestamp'],
                    'type': 'osint',
                    'event': osint_item,
                    'correlation_to_forensic': {
                        'forensic_path': forensic_event['file_path'],
                        'temporal_proximity': osint_corr['temporal_proximity'],
                        'content_relevance': osint_corr['content_relevance']
                    }
                }
                timeline.append(timeline_entry)
        
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline
    
    def generate_correlation_report(self, correlations):
        if not correlations:
            return {
                'summary': 'No correlations found',
                'total_correlations': 0,
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0
            }
        
        high_conf = sum(1 for c in correlations if c['correlation_strength'] > 0.7)
        medium_conf = sum(1 for c in correlations if 0.4 < c['correlation_strength'] <= 0.7)
        low_conf = sum(1 for c in correlations if c['correlation_strength'] <= 0.4)
        
        top_correlations = correlations[:10]
        
        osint_sources = defaultdict(int)
        for correlation in correlations:
            for osint_corr in correlation['osint_correlations']:
                source = osint_corr['osint_item']['source']
                osint_sources[source] += 1
        
        return {
            'summary': f"Found {len(correlations)} correlations between forensic events and OSINT data",
            'total_correlations': len(correlations),
            'confidence_distribution': {
                'high_confidence': high_conf,
                'medium_confidence': medium_conf,
                'low_confidence': low_conf
            },
            'osint_source_breakdown': dict(osint_sources),
            'top_correlations': [
                {
                    'forensic_file': c['forensic_event']['file_path'],
                    'forensic_timestamp': c['forensic_event']['timestamp'].isoformat(),
                    'correlation_strength': c['correlation_strength'],
                    'osint_matches': len(c['osint_correlations']),
                    'top_osint_content': c['osint_correlations'][0]['osint_item']['content'][:200] + '...' if c['osint_correlations'] else ''
                }
                for c in top_correlations
            ]
        }
    
    def find_activity_patterns(self, correlations):
        patterns = {}
        
        time_clusters = self._cluster_by_time(correlations)
        patterns['temporal_clusters'] = time_clusters
        
        file_type_patterns = self._analyze_file_type_patterns(correlations)
        patterns['file_type_correlations'] = file_type_patterns
        
        osint_sentiment_patterns = self._analyze_osint_sentiment_patterns(correlations)
        patterns['sentiment_correlations'] = osint_sentiment_patterns
        
        return patterns
    
    def _cluster_by_time(self, correlations):
        clusters = []
        current_cluster = []
        
        sorted_correlations = sorted(correlations, key=lambda x: x['forensic_event']['timestamp'])
        
        for i, correlation in enumerate(sorted_correlations):
            if not current_cluster:
                current_cluster.append(correlation)
            else:
                time_diff = abs(
                    (correlation['forensic_event']['timestamp'] - 
                     current_cluster[-1]['forensic_event']['timestamp']).total_seconds()
                ) / 3600
                
                if time_diff <= 2:
                    current_cluster.append(correlation)
                else:
                    if len(current_cluster) >= 2:
                        clusters.append({
                            'start_time': current_cluster[0]['forensic_event']['timestamp'],
                            'end_time': current_cluster[-1]['forensic_event']['timestamp'],
                            'event_count': len(current_cluster),
                            'avg_correlation_strength': sum(c['correlation_strength'] for c in current_cluster) / len(current_cluster)
                        })
                    current_cluster = [correlation]
        
        if len(current_cluster) >= 2:
            clusters.append({
                'start_time': current_cluster[0]['forensic_event']['timestamp'],
                'end_time': current_cluster[-1]['forensic_event']['timestamp'],
                'event_count': len(current_cluster),
                'avg_correlation_strength': sum(c['correlation_strength'] for c in current_cluster) / len(current_cluster)
            })
        
        return clusters
    
    def _analyze_file_type_patterns(self, correlations):
        file_type_stats = defaultdict(lambda: {'count': 0, 'avg_strength': 0.0, 'strengths': []})
        
        for correlation in correlations:
            file_type = correlation['forensic_event'].get('file_type', 'unknown')
            file_type_stats[file_type]['count'] += 1
            file_type_stats[file_type]['strengths'].append(correlation['correlation_strength'])
        
        for file_type in file_type_stats:
            strengths = file_type_stats[file_type]['strengths']
            file_type_stats[file_type]['avg_strength'] = sum(strengths) / len(strengths)
        
        return dict(file_type_stats)
    
    def _analyze_osint_sentiment_patterns(self, correlations):
        source_patterns = defaultdict(lambda: {'count': 0, 'avg_strength': 0.0, 'common_terms': defaultdict(int)})
        
        for correlation in correlations:
            for osint_corr in correlation['osint_correlations']:
                osint_item = osint_corr['osint_item']
                source = osint_item['source']
                
                source_patterns[source]['count'] += 1
                
                content_words = self._extract_content_keywords(osint_item['content'])
                for word in content_words[:10]:
                    source_patterns[source]['common_terms'][word] += 1
        
        for source in source_patterns:
            if source_patterns[source]['count'] > 0:
                correlations_for_source = [
                    c for c in correlations 
                    for oc in c['osint_correlations'] 
                    if oc['osint_item']['source'] == source
                ]
                
                if correlations_for_source:
                    source_patterns[source]['avg_strength'] = sum(
                        c['correlation_strength'] for c in correlations_for_source
                    ) / len(correlations_for_source)
        
        return dict(source_patterns)
    
    def generate_llm_investigation_summary(self, correlations, forensic_summary_data, osint_summary_data, context_notes=""):
        # let the LLM write us a nice summary
        
        if not self.llm_client or not self.llm_client.is_available():
            return "LLM-powered analysis not available"
        
        try:
            forensic_summary = f"Forensic Analysis: {len(forensic_summary_data)} events processed" if isinstance(forensic_summary_data, list) else str(forensic_summary_data)
            osint_summary = f"OSINT Collection: {len(osint_summary_data)} items collected" if isinstance(osint_summary_data, list) else str(osint_summary_data)
            
            # add any extra context if we have it
            if context_notes.strip():
                context_info = f"\n\nAdditional Context Notes: {context_notes}"
            else:
                context_info = ""
            
            summary = self.llm_client.summarize_investigation_findings(
                correlations=correlations,
                forensic_summary=forensic_summary + context_info,
                osint_summary=osint_summary
            )
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating LLM investigation summary: {e}")
            return "Unable to generate LLM-powered investigation summary"
    
    def analyze_correlation_patterns_with_llm(self, correlations):
        # have the LLM look for patterns we might miss
        
        if not self.llm_client or not self.llm_client.is_available():
            return None
        
        if not correlations:
            return None
        
        try:
            # format the correlations for the LLM
            correlation_summaries = []
            for corr in correlations[:10]:  # just the top ones to keep it manageable
                forensic_event = corr['forensic_event']
                top_osint = corr['osint_correlations'][0] if corr['osint_correlations'] else None
                
                if top_osint:
                    correlation_summaries.append(
                        f"File: {forensic_event.get('file_path', 'Unknown')} "
                        f"correlates with {top_osint['osint_item'].get('source', 'Unknown')} "
                        f"content (strength: {corr['correlation_strength']:.2f})"
                    )
            
            system_prompt = """You are an expert digital forensics analyst. Analyze correlation patterns to identify:
            - Investigation priorities and focus areas
            - Potential security incidents or threats
            - Timeline significance and event clustering
            - Recommended follow-up actions
            - Key findings and their implications
            
            Provide actionable insights for investigators in a structured format."""
            
            prompt = f"""Analyze these forensic-OSINT correlations for patterns and insights:

Correlations found:
{chr(10).join(correlation_summaries)}

Total correlations: {len(correlations)}
Average strength: {sum(c['correlation_strength'] for c in correlations) / len(correlations):.2f}

Provide investigation insights and recommendations:"""
            
            insights = self.llm_client.generate(prompt, system_prompt, max_tokens=2048)
            return insights
            
        except Exception as e:
            logger.error(f"Error analyzing correlation patterns with LLM: {e}")
            return None