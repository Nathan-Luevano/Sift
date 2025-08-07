import ollama
import logging
import json
from typing import Dict, List, Optional, Any
import time

logger = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self, config):
        self.config = config
        self.client = None
        self.model = config.OLLAMA_MODEL
        self.timeout = config.OLLAMA_TIMEOUT
        self.max_tokens = config.LLM_MAX_TOKENS
        self.temperature = config.LLM_TEMPERATURE
        
        if config.OLLAMA_ENABLE:
            self._initialize_client()
    
    def _initialize_client(self):
        try:
            self.client = ollama.Client(host=self.config.OLLAMA_HOST)
            
            # gotta make sure the connection actually works
            try:
                models_response = self.client.list()
                available_models = []
                
                # ollama likes to return different formats sometimes
                if isinstance(models_response, dict):
                    if 'models' in models_response:
                        for model in models_response['models']:
                            if isinstance(model, dict):
                                model_name = model.get('name', model.get('model', ''))
                            else:
                                model_name = str(model)
                            if model_name:
                                available_models.append(model_name)
                elif isinstance(models_response, list):
                    for model in models_response:
                        if hasattr(model, 'name'):
                            available_models.append(model.name)
                        elif isinstance(model, dict):
                            available_models.append(model.get('name', str(model)))
                        else:
                            available_models.append(str(model))
                
                logger.info(f"Available models: {available_models}")
                
                # see if our model is actually installed
                model_available = False
                for available_model in available_models:
                    if self.model in available_model or available_model.startswith(self.model.split(':')[0]):
                        model_available = True
                        self.model = available_model  # use the exact name it wants
                        break
                
                if not model_available:
                    logger.warning(f"Model {self.model} not found. Available models: {available_models}")
                    
                    # model not found, let's try downloading it
                    logger.info(f"Attempting to pull model {self.model}")
                    try:
                        self.client.pull(self.model)
                        logger.info(f"Successfully pulled model {self.model}")
                    except Exception as e:
                        logger.error(f"Failed to pull model {self.model}: {e}")
                        # if download fails, we'll try something else
                        if available_models:
                            logger.info(f"Using first available model: {available_models[0]}")
                            self.model = available_models[0]
                        else:
                            raise
                
                logger.info(f"Ollama client initialized with model: {self.model}")
                
            except Exception as e:
                logger.error(f"Error checking models: {e}")
                # one last attempt to see if it's working
                test_response = self.client.generate(model=self.model, prompt="test", stream=False)
                logger.info("Ollama connection test successful")
            
        except Exception as e:
            logger.error(f"Failed to initialize Ollama client: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        return self.client is not None and self.config.OLLAMA_ENABLE
    
    def generate(self, prompt: str, system_prompt: str = None, max_tokens: int = None, temperature: float = None) -> Optional[str]:
        if not self.is_available():
            logger.warning("Ollama client not available")
            return None
        
        try:
            messages = []
            
            if system_prompt:
                messages.append({
                    'role': 'system',
                    'content': system_prompt
                })
            
            messages.append({
                'role': 'user',
                'content': prompt
            })
            
            response = self.client.chat(
                model=self.model,
                messages=messages,
                options={
                    'temperature': temperature or self.temperature,
                    'num_predict': max_tokens or self.max_tokens
                }
            )
            
            return response['message']['content'].strip()
            
        except Exception as e:
            logger.error(f"Error generating response from Ollama: {e}")
            return None
    
    def analyze_web_content(self, content: str, context: str = "", question: str = "") -> Optional[Dict[str, Any]]:
        system_prompt = """You are an expert OSINT analyst specializing in digital forensics and intelligence correlation. 
        Your task is to analyze web content and extract relevant information that could correlate with digital forensic evidence.
        
        Focus on:
        - Temporal references (dates, times, events)
        - Geographic references (locations, places)
        - Security-related topics (breaches, incidents, malware)
        - Social movements or events
        - Technical references that might relate to computer systems
        - Suspicious activities or anomalies
        
        Return your analysis as a JSON object with these fields:
        - summary: Brief summary of the content
        - temporal_indicators: List of time/date references found
        - geographic_indicators: List of location references found
        - security_relevance: Security-related topics (0-10 scale)
        - key_entities: Important people, organizations, or systems mentioned
        - suspicious_indicators: Any suspicious activities or anomalies
        - correlation_potential: How likely this content is to correlate with forensic evidence (0-10 scale)
        """
        
        prompt = f"""Analyze the following web content for intelligence correlation potential:

Context: {context}
Question: {question}

Web Content:
{content[:4000]}

Provide analysis as JSON:"""

        try:
            response = self.generate(prompt, system_prompt, max_tokens=2048)
            if response:
                # hopefully the LLM gave us proper JSON
                import re
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
                else:
                    # fallback if the LLM didn't cooperate
                    return {
                        "summary": response[:200],
                        "temporal_indicators": [],
                        "geographic_indicators": [],
                        "security_relevance": 5,
                        "key_entities": [],
                        "suspicious_indicators": [],
                        "correlation_potential": 3
                    }
        except Exception as e:
            logger.error(f"Error analyzing web content: {e}")
            
        return None
    
    def generate_search_queries(self, forensic_context: str, location: str = "", timeframe: str = "") -> List[str]:
        system_prompt = """You are an expert OSINT researcher specializing in forensic-intelligence correlation. Generate highly targeted web search queries based on forensic evidence analysis.

        Create queries that would find content directly related to the forensic findings:
        - Security incidents involving similar file types/activities
        - Public reports of malware/attacks with matching patterns
        - Technical analysis of similar threats or vulnerabilities
        - News articles about cybersecurity incidents in the geographic area
        - Social media discussions about suspicious activities
        - Threat intelligence reports matching the indicators
        
        Important: 
        - Prioritize queries that match specific forensic indicators (file names, types, locations)
        - Include both technical security terms and plain language descriptions
        - Consider geographic and temporal context for relevance
        - Focus on findable, indexable content that would appear in search results
        
        Return only search queries, one per line, maximum 12 queries. Start with the most specific/evidence-based queries."""
        
        prompt = f"""Generate highly targeted web search queries for forensic-OSINT correlation:

FORENSIC EVIDENCE ANALYSIS:
{forensic_context}

INVESTIGATION CONTEXT:
- Location: {location}
- Timeframe: {timeframe}

Generate search queries prioritized by specificity and evidence correlation potential:"""

        try:
            response = self.generate(prompt, system_prompt, max_tokens=1024)
            if response:
                queries = [q.strip() for q in response.split('\n') if q.strip() and not q.strip().startswith('#')]
                return queries[:12]  # don't want too many queries
        except Exception as e:
            logger.error(f"Error generating search queries: {e}")
            
        return []
    
    def analyze_correlation_relevance(self, forensic_event: Dict, osint_content: str) -> Optional[Dict[str, Any]]:
        system_prompt = """You are an expert digital forensics analyst. Analyze the correlation potential between 
        a forensic event and OSINT content. Consider temporal, contextual, and semantic relationships.
        
        Rate correlation strength from 0-10 based on:
        - Temporal proximity and relevance
        - Content similarity and context
        - Geographic correlation
        - Security relevance
        - Suspicious patterns
        
        Return analysis as JSON with:
        - correlation_score: 0-10 rating
        - reasoning: Explanation of the correlation
        - confidence: Confidence level (0-10)
        - key_connections: Specific connections found
        - recommendations: Suggested follow-up actions
        """
        
        forensic_summary = f"""Forensic Event:
- File: {forensic_event.get('file_path', 'Unknown')}
- Event Type: {forensic_event.get('event_type', 'Unknown')}
- Timestamp: {forensic_event.get('timestamp', 'Unknown')}
- File Type: {forensic_event.get('file_type', 'Unknown')}
- Size: {forensic_event.get('file_size', 'Unknown')} bytes"""

        prompt = f"""{forensic_summary}

OSINT Content:
{osint_content[:2000]}

Analyze correlation potential and return as JSON:"""

        try:
            response = self.generate(prompt, system_prompt, max_tokens=1536)
            if response:
                import re
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.error(f"Error analyzing correlation relevance: {e}")
            
        return None
    
    def summarize_investigation_findings(self, correlations: List[Dict], forensic_summary: str, osint_summary: str) -> str:
        system_prompt = """You are an expert digital forensics report writer. Summarize investigation findings 
        in a professional, clear manner suitable for law enforcement or security professionals.
        
        Focus on:
        - Key correlations discovered
        - Timeline of events
        - Geographic patterns
        - Security implications
        - Recommended actions
        
        Write in a clear, professional tone suitable for investigators."""
        
        correlations_summary = f"Found {len(correlations)} correlations with an average strength of " + \
                              f"{sum(c.get('correlation_strength', 0) for c in correlations) / len(correlations):.2f}" if correlations else "No correlations found"
        
        prompt = f"""Investigation Summary:

Forensic Analysis: {forensic_summary}

OSINT Collection: {osint_summary}

Correlations: {correlations_summary}

Generate a comprehensive investigation summary report:"""

        try:
            response = self.generate(prompt, system_prompt, max_tokens=2048, temperature=0.2)
            return response if response else "Unable to generate investigation summary"
        except Exception as e:
            logger.error(f"Error summarizing investigation findings: {e}")
            return "Error generating investigation summary"