import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import time
import hashlib
from urllib.parse import urlparse, urljoin, quote
import re
import json

try:
    from googlesearch import search as google_search
    GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    GOOGLE_SEARCH_AVAILABLE = False

try:
    from serpapi import GoogleSearch
    SERPAPI_AVAILABLE = True
except ImportError:
    SERPAPI_AVAILABLE = False

try:
    from googleapiclient.discovery import build
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False

try:
    from pytrends.request import TrendReq
    PYTRENDS_AVAILABLE = True
except ImportError:
    PYTRENDS_AVAILABLE = False

try:
    import requests_cache
    REQUESTS_CACHE_AVAILABLE = True
except ImportError:
    REQUESTS_CACHE_AVAILABLE = False
    import requests

# scraping libraries
from bs4 import BeautifulSoup
from newspaper import Article, Config as NewspaperConfig
from readability import Document
import markdownify

# different search APIs
from duckduckgo_search import DDGS

# selenium for tricky sites
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

from llm_client import OllamaClient

logger = logging.getLogger(__name__)

class AdvancedWebIntelligenceCollector:
    def __init__(self, config):
        self.config = config
        self.llm_client = OllamaClient(config) if config.OLLAMA_ENABLE else None
        
        # cache stuff so we don't hit APIs too much
        if REQUESTS_CACHE_AVAILABLE:
            self.session = requests_cache.CachedSession(
                cache_name='sift_web_cache',
                expire_after=3600,
                backend='sqlite'
            )
        else:
            self.session = requests.Session()

        # set up all the different search options
        self.search_engines = {
            'google': self._search_google,
            'google_api': self._search_google_api,
            'serpapi': self._search_serpapi,
            'duckduckgo': self._search_duckduckgo,
        }
        
        self.newspaper_config = NewspaperConfig()
        self.newspaper_config.browser_user_agent = config.BROWSER_USER_AGENT
        self.newspaper_config.request_timeout = config.WEB_SCRAPE_TIMEOUT
        
        self.driver = None
        
        if PYTRENDS_AVAILABLE:
            try:
                self.pytrends = TrendReq(hl='en-US', tz=360)
            except:
                self.pytrends = None
        else:
            self.pytrends = None
            
        logger.info("Advanced Web Intelligence Collector initialized")
    
    def collect_comprehensive_intelligence(self, forensic_context: Dict, location: str = "", start_time: datetime = None, end_time: datetime = None) -> List[Dict[str, Any]]:
        
        if not self.config.WEB_SEARCH_ENABLE:
            logger.info("Web search is disabled")
            return []
        
        logger.info("Starting comprehensive web intelligence collection")
        
        all_results = []
        
        # first, generate smart queries
        search_queries = self._generate_advanced_search_queries(forensic_context, location, start_time, end_time)
        
        if not search_queries:
            logger.warning("No search queries generated")
            return []
        
        logger.info(f"Generated {len(search_queries)} advanced search queries")
        
        # search across multiple engines
        if self.config.SEARCH_STRATEGY == 'multi_engine':
            all_results.extend(self._execute_multi_engine_search(search_queries))
        else:
            all_results.extend(self._execute_single_engine_search(search_queries))
        
        # hit social media and specialized sources
        if self.config.ENABLE_SOCIAL_SEARCH:
            all_results.extend(self._search_social_platforms(search_queries, location))
        
        # check news archives and academic stuff
        if self.config.ENABLE_NEWS_ARCHIVE_SEARCH:
            all_results.extend(self._search_news_archives(search_queries, start_time, end_time))
        
        # analyze trends if we can
        if self.pytrends and forensic_context:
            trend_data = self._analyze_search_trends(search_queries, location)
            if trend_data:
                all_results.extend(trend_data)
        
        # process and clean up the results
        processed_results = self._process_and_analyze_results(all_results, forensic_context)
        
        # filter and rank by relevance
        final_results = self._advanced_filtering_and_ranking(processed_results, forensic_context)
        
        logger.info(f"Collected {len(final_results)} high-quality web intelligence items")
        
        return final_results[:self.config.MAX_OSINT_RESULTS]
    
    def _generate_advanced_search_queries(self, forensic_context: Dict, location: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        queries = []
        
        # let the LLM generate smart queries
        if self.llm_client and self.llm_client.is_available():
            llm_queries = self._generate_llm_queries(forensic_context, location, start_time, end_time)
            queries.extend(llm_queries)
        
        # add some rule-based queries too for good measure
        rule_based_queries = self._generate_rule_based_queries(forensic_context, location, start_time, end_time)
        queries.extend(rule_based_queries)
        
        # throw in some forensic-specific searches
        forensic_queries = self._generate_forensic_specific_queries(forensic_context, location)
        queries.extend(forensic_queries)
        
        return self._deduplicate_queries(queries)
    
    def _generate_llm_queries(self, forensic_context: Dict, location: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        system_prompt = """You are an expert OSINT investigator and digital forensics analyst. Generate highly targeted search queries for web intelligence collection.

Your queries should be designed to find:
1. Security incidents, breaches, and cyberattacks in the target area
2. Malware campaigns and threat actor activities  
3. Social media discussions about suspicious activities
4. News reports about cybersecurity incidents
5. Academic papers and research about relevant threats
6. Dark web mentions and underground forum discussions
7. Government advisories and security bulletins
8. Corporate security announcements
9. Law enforcement activities and arrests
10. Technical analysis and threat intelligence reports

Create queries that use advanced Google search operators:
- Use quotes for exact phrases: "cybersecurity incident"
- Use site: for specific domains: site:reddit.com
- Use intitle: for title searches: intitle:"data breach"
- Use inurl: for URL searches: inurl:security
- Use filetype: for document searches: filetype:pdf
- Use daterange: for time-specific searches
- Use location-specific terms and regional identifiers
- Use industry-specific terminology
- Use threat actor names and campaign identifiers

Return 15-25 diverse, targeted search queries as a JSON array."""
        
        context_parts = []
        if isinstance(forensic_context, dict):
            if forensic_context.get('file_types'):
                context_parts.append(f"File types: {', '.join(forensic_context['file_types'])}")
            if forensic_context.get('suspicious_files'):
                context_parts.append(f"Suspicious files: {', '.join(forensic_context['suspicious_files'][:5])}")
            if forensic_context.get('event_types'):
                context_parts.append(f"Activity types: {', '.join(forensic_context['event_types'])}")
        
        timeframe = ""
        if start_time and end_time:
            timeframe = f"Time period: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}"
        
        prompt = f"""Generate advanced web search queries for OSINT collection:

Location: {location}
{timeframe}
Forensic Context: {'. '.join(context_parts)}

Generate sophisticated search queries that will find relevant intelligence about potential security incidents, cyber threats, and suspicious activities in this context. Focus on queries that will surface high-value information from news sites, social media, security blogs, government sources, and technical forums.

Return as JSON array:"""

        try:
            response = self.llm_client.generate(prompt, system_prompt, max_tokens=2048)
            if response:
                import json
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                if json_match:
                    query_list = json.loads(json_match.group())
                    return [{'query': q, 'type': 'llm_generated', 'priority': 'high'} for q in query_list if isinstance(q, str)]
        except Exception as e:
            logger.debug(f"LLM query generation failed: {e}")
        
        return []
    
    def _generate_rule_based_queries(self, forensic_context: Dict, location: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        queries = []
        
        # location-specific security searches
        if location:
            location_queries = [
                f'"{location}" cybersecurity incident',
                f'"{location}" data breach',
                f'"{location}" cyber attack',
                f'"{location}" malware campaign',
                f'"{location}" security alert',
                f'"{location}" hacker arrest',
                f'site:reddit.com "{location}" cyber',
                f'site:twitter.com "{location}" breach',
                f'intitle:"security incident" "{location}"',
                f'filetype:pdf cybersecurity "{location}"'
            ]
            queries.extend([{'query': q, 'type': 'location_based', 'priority': 'high'} for q in location_queries])
        
        if isinstance(forensic_context, dict):
            for file_type in forensic_context.get('file_types', [])[:5]:
                if file_type in ['exe', 'dll', 'bat', 'ps1', 'scr']:
                    queries.extend([
                        {'query': f'malware "{file_type}" analysis', 'type': 'forensic', 'priority': 'medium'},
                        {'query': f'threat intelligence "{file_type}" campaign', 'type': 'forensic', 'priority': 'medium'},
                        {'query': f'site:virustotal.com "{file_type}"', 'type': 'forensic', 'priority': 'low'}
                    ])
            
            for susp_file in forensic_context.get('suspicious_files', [])[:3]:
                filename = susp_file.split('/')[-1] if '/' in susp_file else susp_file
                if len(filename) > 3:
                    queries.append({
                        'query': f'"{filename}" malware analysis',
                        'type': 'suspicious_file',
                        'priority': 'high'
                    })
        
        if start_time and end_time:
            year = start_time.year
            month_name = start_time.strftime('%B')
            
            time_queries = [
                f'cybersecurity incident {year}',
                f'data breach "{month_name} {year}"',
                f'cyber attack timeline {year}',
                f'security alert {year}'
            ]
            queries.extend([{'query': q, 'type': 'temporal', 'priority': 'medium'} for q in time_queries])
        
        threat_queries = [
            'APT campaign analysis',
            'ransomware group activity',
            'threat actor attribution',
            'cyber criminal arrest',
            'dark web marketplace',
            'zero day exploit',
            'incident response report',
            'threat intelligence bulletin'
        ]
        queries.extend([{'query': q, 'type': 'threat_intel', 'priority': 'medium'} for q in threat_queries])
        
        return queries
    
    def _generate_forensic_specific_queries(self, forensic_context: Dict, location: str) -> List[Dict[str, Any]]:
        queries = []
        
        tech_queries = [
            'digital forensics case study',
            'incident response timeline',
            'malware analysis report',
            'forensic artifact analysis',
            'network intrusion detection',
            'endpoint detection response',
            'threat hunting methodology',
            'cyber forensics investigation'
        ]
        
        if location:
            tech_queries.extend([
                f'computer forensics "{location}"',
                f'cybersecurity investigation "{location}"',
                f'digital evidence "{location}"'
            ])
        
        queries.extend([{'query': q, 'type': 'forensic_technical', 'priority': 'low'} for q in tech_queries])
        
        return queries
    
    def _execute_multi_engine_search(self, search_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # run searches on multiple engines
        
        results = []
        
        # do the important searches first
        high_priority = [q for q in search_queries if q.get('priority') == 'high']
        medium_priority = [q for q in search_queries if q.get('priority') == 'medium']
        
        # use the good engines for important stuff
        for query_data in high_priority[:10]:  # don't want to get rate limited
            query = query_data['query']
            
            # Google usually gives the best results
            if self.config.GOOGLE_SEARCH_API_KEY:
                results.extend(self._search_google_api(query))
                time.sleep(1)  # be nice to the APIs
            elif self.config.SERPAPI_KEY:
                results.extend(self._search_serpapi(query))
                time.sleep(1)
            else:
                results.extend(self._search_google(query))
                time.sleep(2)  # unofficial APIs need more breathing room
            
            # DDG as backup
            results.extend(self._search_duckduckgo(query))
            time.sleep(0.5)
        
        # DDG is fine for the medium priority stuff
        for query_data in medium_priority[:15]:
            results.extend(self._search_duckduckgo(query_data['query']))
            time.sleep(0.5)
        
        return results
    
    def _execute_single_engine_search(self, search_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Execute searches using single configured engine
        
        results = []
        engine = self.config.WEB_SEARCH_ENGINE.lower()
        
        if engine not in self.search_engines:
            logger.warning(f"Unknown search engine: {engine}, falling back to DuckDuckGo")
            engine = 'duckduckgo'
        
        search_func = self.search_engines[engine]
        
        for query_data in search_queries[:20]:  # Limit total queries
            try:
                query_results = search_func(query_data['query'])
                results.extend(query_results)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                logger.debug(f"Search failed for query '{query_data['query']}': {e}")
                continue
        
        return results
    
    def _search_google(self, query: str) -> List[Dict[str, Any]]:
        # Search using unofficial Google search
        results = []
        
        if not GOOGLE_SEARCH_AVAILABLE:
            logger.warning("Google search not available, falling back to DuckDuckGo")
            return self._search_duckduckgo(query)
        
        try:
            for url in google_search(query, num=10, stop=10, pause=2):
                results.append({
                    'title': '',  # Will be extracted during content analysis
                    'url': url,
                    'snippet': '',
                    'source': 'google_unofficial'
                })
        except Exception as e:
            logger.debug(f"Google search error: {e}")
        
        return results
    
    def _search_google_api(self, query: str) -> List[Dict[str, Any]]:
        # Search using official Google Custom Search API
        if not GOOGLE_API_AVAILABLE:
            logger.warning("Google API not available")
            return []
            
        if not self.config.GOOGLE_SEARCH_API_KEY or not self.config.GOOGLE_SEARCH_ENGINE_ID:
            return []
        
        results = []
        
        try:
            service = build("customsearch", "v1", developerKey=self.config.GOOGLE_SEARCH_API_KEY)
            search_result = service.cse().list(
                q=query,
                cx=self.config.GOOGLE_SEARCH_ENGINE_ID,
                num=10
            ).execute()
            
            for item in search_result.get('items', []):
                results.append({
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'snippet': item.get('snippet', ''),
                    'source': 'google_api'
                })
                
        except Exception as e:
            logger.debug(f"Google API search error: {e}")
        
        return results
    
    def _search_serpapi(self, query: str) -> List[Dict[str, Any]]:
        # Search using SerpApi (premium Google search API)
        if not SERPAPI_AVAILABLE:
            logger.warning("SerpApi not available")
            return []
            
        if not self.config.SERPAPI_KEY:
            return []
        
        results = []
        
        try:
            search = GoogleSearch({
                "q": query,
                "api_key": self.config.SERPAPI_KEY,
                "num": 10
            })
            
            search_results = search.get_dict()
            
            for item in search_results.get('organic_results', []):
                results.append({
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'snippet': item.get('snippet', ''),
                    'source': 'serpapi'
                })
                
        except Exception as e:
            logger.debug(f"SerpApi search error: {e}")
        
        return results
    
    def _search_duckduckgo(self, query: str) -> List[Dict[str, Any]]:
        # Search using DuckDuckGo
        results = []
        
        try:
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(
                    keywords=query,
                    max_results=15,
                    timelimit='y',
                    safesearch='off'
                ))
                
                for result in ddg_results:
                    results.append({
                        'title': result.get('title', ''),
                        'url': result.get('href', ''),
                        'snippet': result.get('body', ''),
                        'source': 'duckduckgo'
                    })
                    
        except Exception as e:
            logger.debug(f"DuckDuckGo search error: {e}")
        
        return results
    
    def _search_social_platforms(self, search_queries: List[Dict[str, Any]], location: str) -> List[Dict[str, Any]]:
        # Search social media platforms for relevant discussions
        
        results = []
        
        # Focus on high-priority queries for social search
        high_priority_queries = [q['query'] for q in search_queries if q.get('priority') == 'high'][:5]
        
        for query in high_priority_queries:
            # Reddit searches
            reddit_queries = [
                f'site:reddit.com "{query}"',
                f'site:reddit.com/r/cybersecurity "{query}"',
                f'site:reddit.com/r/netsec "{query}"'
            ]
            
            for reddit_query in reddit_queries:
                try:
                    reddit_results = self._search_duckduckgo(reddit_query)
                    for result in reddit_results:
                        result['platform'] = 'reddit'
                        result['content_type'] = 'social'
                    results.extend(reddit_results)
                    time.sleep(1)
                except:
                    continue
            
            # Twitter/X searches (through DuckDuckGo)
            twitter_queries = [
                f'site:twitter.com "{query}"',
                f'site:x.com "{query}"'
            ]
            
            for twitter_query in twitter_queries:
                try:
                    twitter_results = self._search_duckduckgo(twitter_query)
                    for result in twitter_results:
                        result['platform'] = 'twitter'
                        result['content_type'] = 'social'
                    results.extend(twitter_results)
                    time.sleep(1)
                except:
                    continue
        
        return results
    
    def _search_news_archives(self, search_queries: List[Dict[str, Any]], start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        # Search news archives and specialized sources
        
        results = []
        
        # Focus on high-priority queries for news search
        high_priority_queries = [q['query'] for q in search_queries if q.get('priority') == 'high'][:3]
        
        for query in high_priority_queries:
            # Security-focused news sites
            news_sites = [
                'site:krebsonsecurity.com',
                'site:threatpost.com',
                'site:darkreading.com',
                'site:securityweek.com',
                'site:bleepingcomputer.com',
                'site:cyberscoop.com'
            ]
            
            for site in news_sites[:3]:  # Limit to avoid too many requests
                news_query = f'{site} "{query}"'
                try:
                    news_results = self._search_duckduckgo(news_query)
                    for result in news_results:
                        result['content_type'] = 'security_news'
                        result['site_type'] = 'security_publication'
                    results.extend(news_results)
                    time.sleep(1)
                except:
                    continue
        
        return results
    
    def _analyze_search_trends(self, search_queries: List[Dict[str, Any]], location: str) -> List[Dict[str, Any]]:
        # Analyze search trends using Google Trends
        
        if not self.pytrends:
            return []
        
        results = []
        
        try:
            # Extract keywords from queries
            keywords = []
            for query_data in search_queries[:5]:  # Limit to avoid API limits
                query = query_data['query']
                # Simple keyword extraction
                clean_query = re.sub(r'[^\w\s]', ' ', query)
                words = [w for w in clean_query.split() if len(w) > 3]
                keywords.extend(words[:2])  # Take first 2 meaningful words
            
            # Get unique keywords
            unique_keywords = list(set(keywords))[:5]
            
            if unique_keywords:
                self.pytrends.build_payload(unique_keywords, timeframe='today 12-m')
                interest_over_time = self.pytrends.interest_over_time()
                
                if not interest_over_time.empty:
                    trends_data = {
                        'timestamp': datetime.now(),
                        'source': 'google_trends',
                        'title': 'Search Trends Analysis',
                        'content': f'Trend analysis for keywords: {", ".join(unique_keywords)}',
                        'url': 'https://trends.google.com',
                        'data': {
                            'keywords': unique_keywords,
                            'trends': interest_over_time.to_dict(),
                            'location': location
                        },
                        'content_type': 'trend_analysis',
                        'relevance_score': 6
                    }
                    
                    results.append(trends_data)
                    
        except Exception as e:
            logger.debug(f"Google Trends analysis failed: {e}")
        
        return results
    
    def _process_and_analyze_results(self, results: List[Dict[str, Any]], forensic_context: Dict) -> List[Dict[str, Any]]:
        # Enhanced content processing and analysis
        
        processed_results = []
        
        for result in results:
            try:
                # Extract content using multiple methods
                content = self._extract_content_enhanced(result)
                
                if not content or len(content) < 50:
                    continue
                
                # Enhanced LLM analysis
                analysis = self._analyze_content_with_llm(content, forensic_context, result)
                
                # Build enhanced result object
                enhanced_result = {
                    'timestamp': datetime.now(),
                    'source': 'web_intelligence_advanced',
                    'url': result.get('url', ''),
                    'title': result.get('title', ''),
                    'content': content[:2000],  # Limit content length
                    'full_content': content,
                    'snippet': result.get('snippet', ''),
                    'search_source': result.get('source', 'unknown'),
                    'platform': result.get('platform', ''),
                    'content_type': result.get('content_type', 'web_page'),
                    'site_type': result.get('site_type', ''),
                    'relevance_score': analysis.get('relevance_score', 3) if analysis else 3,
                    'security_score': analysis.get('security_relevance', 0) if analysis else 0,
                    'analysis': analysis,
                    'author': 'Advanced Web Intelligence',
                    'location': '',
                    'coordinates': None,
                    'engagement': {},
                    'data': {
                        'domain': urlparse(result.get('url', '')).netloc,
                        'content_length': len(content),
                        'extraction_timestamp': datetime.now().isoformat(),
                        'extraction_method': 'advanced_multi_stage'
                    }
                }
                
                processed_results.append(enhanced_result)
                
            except Exception as e:
                logger.debug(f"Error processing result {result.get('url', 'unknown')}: {e}")
                continue
        
        return processed_results
    
    def _extract_content_enhanced(self, search_result: Dict) -> Optional[str]:
        # Multi-stage content extraction with fallbacks
        
        url = search_result.get('url', '')
        if not url:
            return None
        
        # Stage 1: Try newspaper3k (best for articles)
        content = self._extract_with_newspaper(url)
        if content and len(content) > 200:
            return content
        
        # Stage 2: Try readability + requests
        content = self._extract_with_readability(url)
        if content and len(content) > 200:
            return content
        
        # Stage 3: Try basic requests + BeautifulSoup
        content = self._extract_with_beautifulsoup(url)
        if content and len(content) > 200:
            return content
        
        # Stage 4: Browser automation for dynamic content
        if len(search_result.get('snippet', '')) < 100:  # Only if snippet is poor
            content = self._extract_with_browser_enhanced(url)
            if content and len(content) > 200:
                return content
        
        # Fallback: Use snippet if available
        return search_result.get('snippet', '')
    
    def _extract_with_newspaper(self, url: str) -> Optional[str]:
        # Extract content using newspaper3k
        try:
            article = Article(url, config=self.newspaper_config)
            article.download()
            article.parse()
            
            if article.text and len(article.text) > 100:
                content = f"{article.title}\n\n{article.text}"
                if article.summary:
                    content += f"\n\nSummary: {article.summary}"
                return content
        except Exception as e:
            logger.debug(f"Newspaper extraction failed for {url}: {e}")
        
        return None
    
    def _extract_with_readability(self, url: str) -> Optional[str]:
        # Extract content using readability
        try:
            response = self.session.get(url, timeout=self.config.WEB_SCRAPE_TIMEOUT)
            response.raise_for_status()
            
            # Use text content instead of bytes for readability
            doc = Document(response.text)
            clean_html = doc.summary()
            text_content = markdownify.markdownify(clean_html)
            
            # Clean up
            text_content = re.sub(r'\n\s*\n', '\n\n', text_content)
            text_content = re.sub(r'[^\S\r\n]+', ' ', text_content)
            
            return text_content.strip()
            
        except Exception as e:
            logger.debug(f"Readability extraction failed for {url}: {e}")
        
        return None
    
    def _extract_with_beautifulsoup(self, url: str) -> Optional[str]:
        # Extract content using BeautifulSoup
        try:
            response = self.session.get(url, timeout=self.config.WEB_SCRAPE_TIMEOUT)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Try to find main content areas
            main_content = soup.find('main') or soup.find('article') or soup.find(class_='content')
            
            if main_content:
                text = main_content.get_text()
            else:
                text = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            
            return text
            
        except Exception as e:
            logger.debug(f"BeautifulSoup extraction failed for {url}: {e}")
        
        return None
    
    def _extract_with_browser_enhanced(self, url: str) -> Optional[str]:
        # Enhanced browser extraction for dynamic content
        if not self._setup_browser_enhanced():
            return None
        
        try:
            self.driver.get(url)
            
            # Wait for content to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Try multiple content selectors
            content_selectors = [
                'main article', 'article', 'main', '.post-content', '.entry-content',
                '.article-body', '.story-body', '#content', '.content', '#main-content'
            ]
            
            content = ""
            for selector in content_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements and elements[0].text:
                        content = elements[0].text
                        break
                except:
                    continue
            
            # Fallback to body
            if not content:
                body_element = self.driver.find_element(By.TAG_NAME, "body")
                content = body_element.text
            
            return content
            
        except Exception as e:
            logger.debug(f"Enhanced browser extraction failed for {url}: {e}")
            return None
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                    self.driver = None
                except:
                    pass
    
    def _setup_browser_enhanced(self) -> bool:
        # Setup enhanced browser with better options
        if self.driver:
            return True
        
        try:
            chrome_options = ChromeOptions()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            chrome_options.add_argument(f'--user-agent={self.config.BROWSER_USER_AGENT}')
            
            if self.config.BROWSER_HEADLESS:
                chrome_options.add_argument('--headless')
            
            self.driver = webdriver.Chrome(
                service=webdriver.chrome.service.Service(ChromeDriverManager().install()),
                options=chrome_options
            )
            
            # Execute script to avoid detection
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            return True
                
        except Exception as e:
            logger.error(f"Enhanced browser setup failed: {e}")
        
        return False
    
    def _analyze_content_with_llm(self, content: str, forensic_context: Dict, result: Dict) -> Optional[Dict[str, Any]]:
        # Enhanced LLM content analysis
        
        if not self.llm_client or not self.llm_client.is_available():
            return None
        
        system_prompt = """You are an expert OSINT analyst and digital forensics investigator. Analyze web content for intelligence value and correlation potential with digital forensic evidence.

Rate the content on these dimensions (0-10 scale):
- security_relevance: How relevant is this to cybersecurity/digital forensics?
- correlation_potential: How likely is this to correlate with forensic evidence?
- intelligence_value: How valuable is this for intelligence purposes?
- credibility: How credible and reliable is this source/content?
- actionability: How actionable is the information provided?

Also identify:
- key_entities: People, organizations, systems, malware names
- indicators: IOCs, TTPs, threat indicators
- temporal_references: Time periods, dates, events mentioned
- geographic_references: Locations, regions mentioned
- threat_types: Types of threats or attacks mentioned
- relevance_summary: Brief summary of why this is relevant

Return as JSON object."""
        
        context_summary = ""
        if isinstance(forensic_context, dict):
            context_parts = []
            if forensic_context.get('file_types'):
                context_parts.append(f"File types: {', '.join(forensic_context['file_types'][:3])}")
            if forensic_context.get('suspicious_files'):
                context_parts.append(f"Suspicious files: {', '.join([f.split('/')[-1] for f in forensic_context['suspicious_files'][:3]])}")
            context_summary = ". ".join(context_parts)
        
        prompt = f"""Analyze this web content for intelligence correlation potential:

Forensic Context: {context_summary}
Source: {result.get('url', 'Unknown')}
Platform: {result.get('platform', 'web')}
Content Type: {result.get('content_type', 'unknown')}

Content to analyze:
{content[:3000]}

Provide detailed analysis as JSON:"""

        try:
            response = self.llm_client.generate(prompt, system_prompt, max_tokens=1536)
            if response:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    # Calculate overall relevance score
                    if all(key in analysis for key in ['security_relevance', 'correlation_potential', 'intelligence_value']):
                        relevance_score = (
                            analysis['security_relevance'] * 0.4 +
                            analysis['correlation_potential'] * 0.4 +
                            analysis['intelligence_value'] * 0.2
                        )
                        analysis['relevance_score'] = relevance_score
                    
                    return analysis
        except Exception as e:
            logger.debug(f"LLM content analysis failed: {e}")
        
        return None
    
    def _advanced_filtering_and_ranking(self, results: List[Dict[str, Any]], forensic_context: Dict) -> List[Dict[str, Any]]:
        # Enhanced filtering and ranking with evidence-based scoring
        
        # Filter out low-quality results
        filtered_results = []
        
        # Configuration for relevance thresholds
        MIN_RELEVANCE_SCORE = 4.0  # Minimum score to be included
        MIN_CONTENT_LENGTH = 150   # Minimum content length
        
        for result in results:
            # Basic quality filters
            content_length = len(result.get('content', ''))
            relevance_score = result.get('relevance_score', 0)
            security_score = result.get('security_score', 0)
            
            # Skip low-quality results
            if content_length < MIN_CONTENT_LENGTH:
                logger.debug(f"Filtering out short content: {result.get('url', 'Unknown')} ({content_length} chars)")
                continue
                
            # Apply evidence-based relevance scoring
            enhanced_score = self._calculate_evidence_based_relevance(result, forensic_context)
            result['evidence_relevance_score'] = enhanced_score
            
            # Use the higher of LLM relevance or evidence-based relevance
            final_score = max(relevance_score, enhanced_score)
            
            # Apply minimum threshold
            if final_score < MIN_RELEVANCE_SCORE:
                logger.debug(f"Filtering out low relevance content: {result.get('url', 'Unknown')} (score: {final_score:.1f})")
                continue
            
            result['final_relevance_score'] = final_score
            
            # Boost security-focused content that meets evidence criteria
            if security_score > 5 and enhanced_score > 3:
                result['final_relevance_score'] = min(10, result['final_relevance_score'] + 1.5)
                result['boost_reason'] = 'High security relevance with evidence correlation'
            
            # Boost credible sources with evidence correlation
            domain = result.get('data', {}).get('domain', '')
            trusted_domains = [
                'krebsonsecurity.com', 'threatpost.com', 'darkreading.com', 'bleepingcomputer.com',
                'securityweek.com', 'cyberscoop.com', 'theregister.com', 'zdnet.com', 'arstechnica.com'
            ]
            if any(trusted in domain for trusted in trusted_domains) and enhanced_score > 2:
                result['final_relevance_score'] = min(10, result['final_relevance_score'] + 1)
                result['boost_reason'] = result.get('boost_reason', '') + ' Trusted security source'
            
            # Add relevance explanation for transparency
            result['relevance_explanation'] = self._generate_relevance_explanation(result, forensic_context)
            
            filtered_results.append(result)
        
        logger.info(f"Filtered {len(results)} results down to {len(filtered_results)} high-relevance items (threshold: {MIN_RELEVANCE_SCORE})")
        
        # Deduplicate based on content similarity
        unique_results = self._deduplicate_by_content_similarity(filtered_results)
        
        # Sort by enhanced relevance score
        ranked_results = sorted(
            unique_results,
            key=lambda x: (
                x.get('final_relevance_score', 0),
                x.get('evidence_relevance_score', 0),
                x.get('security_score', 0)
            ),
            reverse=True
        )
        
        # Limit to top results to prevent information overload
        MAX_RESULTS = 25
        top_results = ranked_results[:MAX_RESULTS]
        
        logger.info(f"Returning top {len(top_results)} results (max: {MAX_RESULTS})")
        return top_results
    
    def _calculate_evidence_based_relevance(self, result: Dict[str, Any], forensic_context: Dict) -> float:
        """Calculate relevance score based on forensic evidence correlation"""
        
        content = result.get('content', '').lower()
        title = result.get('title', '').lower()
        url = result.get('url', '').lower()
        
        relevance_score = 0.0
        
        # Check for direct file name matches from forensic evidence
        if forensic_context.get('suspicious_files'):
            for file_path in forensic_context['suspicious_files'][:10]:
                file_name = file_path.split('/')[-1].lower()
                if len(file_name) > 3 and (file_name in content or file_name in title):
                    relevance_score += 3.0
                    logger.debug(f"File name match found: {file_name}")
        
        # Check for file type correlations
        if forensic_context.get('file_types'):
            security_file_types = {'file', 'executable', 'script', 'registry', 'log'}
            forensic_file_types = set(forensic_context['file_types'])
            
            if forensic_file_types.intersection(security_file_types):
                security_keywords = [
                    'malware', 'virus', 'trojan', 'exploit', 'vulnerability',
                    'attack', 'breach', 'compromise', 'threat', 'suspicious',
                    'executable', 'payload', 'backdoor', 'rootkit'
                ]
                
                for keyword in security_keywords:
                    if keyword in content:
                        relevance_score += 1.0
        
        # Check for event type correlations
        if forensic_context.get('event_types'):
            event_keywords = {
                'modified': ['change', 'modify', 'alter', 'update', 'edit'],
                'created': ['create', 'new', 'generate', 'install'],
                'accessed': ['access', 'open', 'read', 'view'],
                'deleted': ['delete', 'remove', 'erase', 'clean']
            }
            
            for event_type in forensic_context['event_types']:
                if event_type in event_keywords:
                    for keyword in event_keywords[event_type]:
                        if keyword in content:
                            relevance_score += 0.5
        
        # Location-based correlation
        location = forensic_context.get('location', '')
        if location and len(location) > 3:
            location_terms = location.lower().split()
            for term in location_terms:
                if len(term) > 3 and term in content:
                    relevance_score += 1.5
                    logger.debug(f"Location match found: {term}")
        
        # Timeframe correlation (check if content mentions recent dates)
        timeframe = forensic_context.get('timeframe', '')
        if timeframe:
            # Extract year from timeframe
            import re
            years = re.findall(r'20\d{2}', timeframe)
            for year in years:
                if year in content:
                    relevance_score += 1.0
        
        # Context notes correlation
        context_notes = forensic_context.get('context_notes', '')
        if context_notes:
            # Extract key terms from context notes
            key_terms = re.findall(r'\b[a-zA-Z]{4,}\b', context_notes.lower())
            for term in key_terms[:10]:  # Limit to avoid over-weighting
                if term in content and term not in ['this', 'that', 'with', 'from', 'they', 'have', 'been', 'will']:
                    relevance_score += 0.8
        
        # Source credibility boost
        domain = result.get('data', {}).get('domain', '')
        if any(trusted in domain for trusted in ['github.com', 'stackoverflow.com', 'reddit.com']):
            if relevance_score > 2:  # Only boost if already relevant
                relevance_score += 0.5
        
        return min(relevance_score, 10.0)  # Cap at 10
    
    def _generate_relevance_explanation(self, result: Dict[str, Any], forensic_context: Dict) -> str:
        """Generate human-readable explanation of why content is relevant"""
        
        explanations = []
        
        # Check LLM analysis
        analysis = result.get('analysis', {})
        if analysis and analysis.get('relevance_score', 0) > 5:
            if analysis.get('reasoning'):
                explanations.append(f"LLM Analysis: {analysis['reasoning'][:100]}...")
        
        # Check evidence-based scoring
        evidence_score = result.get('evidence_relevance_score', 0)
        if evidence_score > 3:
            explanations.append(f"High evidence correlation (score: {evidence_score:.1f})")
        
        # Check for specific matches
        content = result.get('content', '').lower()
        
        if forensic_context.get('suspicious_files'):
            for file_path in forensic_context['suspicious_files'][:3]:
                file_name = file_path.split('/')[-1]
                if len(file_name) > 3 and file_name.lower() in content:
                    explanations.append(f"Mentions forensic file: {file_name}")
        
        # Check security relevance
        security_score = result.get('security_score', 0)
        if security_score > 6:
            explanations.append(f"High security relevance (score: {security_score})")
        
        # Check boost reasons
        boost_reason = result.get('boost_reason', '')
        if boost_reason:
            explanations.append(boost_reason.strip())
        
        if not explanations:
            return "Relevant based on content analysis"
        
        return ". ".join(explanations[:3])  # Limit to 3 most important explanations
    
    def _deduplicate_by_content_similarity(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Advanced deduplication based on content similarity
        
        unique_results = []
        seen_hashes = set()
        seen_urls = set()
        
        for result in results:
            url = result.get('url', '')
            content = result.get('content', '')
            
            # Skip duplicate URLs
            if url in seen_urls:
                continue
            
            # Create content fingerprint
            content_words = set(re.findall(r'\b\w{4,}\b', content.lower()))
            content_hash = hashlib.md5(str(sorted(content_words)).encode()).hexdigest()
            
            # Skip very similar content
            if content_hash in seen_hashes:
                continue
            
            seen_urls.add(url)
            seen_hashes.add(content_hash)
            unique_results.append(result)
        
        return unique_results
    
    def _deduplicate_queries(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Deduplicate search queries
        
        seen_queries = set()
        unique_queries = []
        
        for query_data in queries:
            query = query_data['query'].lower().strip()
            if query not in seen_queries and len(query) > 5:
                seen_queries.add(query)
                unique_queries.append(query_data)
        
        return unique_queries
    
    def __del__(self):
        # Cleanup resources
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except:
                pass