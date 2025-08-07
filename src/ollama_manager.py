import ollama
import logging
import json
from typing import Dict, List, Optional, Any
import requests
import time

logger = logging.getLogger(__name__)

class OllamaModelManager:
    def __init__(self, config):
        self.config = config
        self.client = None
        self.recommended_models = [
            {
                'name': 'gemma:7b',
                'description': 'Google Gemma 7B - Excellent for general analysis and reasoning',
                'size': '4.1 GB',
                'memory_req': '8 GB RAM',
                'use_case': 'General forensic analysis, good balance of speed and quality'
            },
            {
                'name': 'gemma:2b',
                'description': 'Google Gemma 2B - Fast and lightweight',
                'size': '1.4 GB', 
                'memory_req': '3 GB RAM',
                'use_case': 'Quick analysis, limited resources'
            },
            {
                'name': 'llama3.1:8b',
                'description': 'Meta Llama 3.1 8B - Advanced reasoning and analysis',
                'size': '4.7 GB',
                'memory_req': '10 GB RAM',
                'use_case': 'Complex pattern recognition, detailed analysis'
            },
            {
                'name': 'mistral:7b',
                'description': 'Mistral 7B - Fast inference, efficient',
                'size': '4.1 GB',
                'memory_req': '8 GB RAM', 
                'use_case': 'Fast responses, good for real-time analysis'
            },
            {
                'name': 'codellama:7b',
                'description': 'Code Llama 7B - Specialized for technical content',
                'size': '3.8 GB',
                'memory_req': '8 GB RAM',
                'use_case': 'Code analysis, technical investigations'
            },
            {
                'name': 'llama3.1:70b',
                'description': 'Meta Llama 3.1 70B - Highest quality analysis',
                'size': '40 GB',
                'memory_req': '64 GB RAM',
                'use_case': 'Maximum accuracy, professional investigations'
            }
        ]
        
        self._initialize_client()
    
    def _initialize_client(self):
        # set up connection to ollama
        try:
            self.client = ollama.Client(host=self.config.OLLAMA_HOST)
            # make sure it's actually working
            self.client.list()
            logger.info("Ollama model manager initialized")
        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            self.client = None
    
    def is_ollama_available(self) -> bool:
        # see if ollama is up and responding
        try:
            if not self.client:
                self._initialize_client()
            
            if self.client:
                self.client.list()
                return True
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
        
        return False
    
    def get_installed_models(self) -> List[Dict[str, Any]]:
        # find out what models we have
        if not self.is_ollama_available():
            return []
        
        try:
            models_response = self.client.list()
            models = []
            
            if isinstance(models_response, dict) and 'models' in models_response:
                for model in models_response['models']:
                    if isinstance(model, dict):
                        model_info = {
                            'name': model.get('name', model.get('model', '')),
                            'size': model.get('size', 0),
                            'modified': model.get('modified_at', ''),
                            'details': model.get('details', {}),
                            'digest': model.get('digest', ''),
                            'status': 'installed'
                        }
                        if model_info['name']:
                            models.append(model_info)
            
            return models
            
        except Exception as e:
            logger.error(f"Error getting installed models: {e}")
            return []
    
    def get_recommended_models(self) -> List[Dict[str, Any]]:
        # models that work well for this kind of analysis
        return self.recommended_models.copy()
    
    def get_model_status(self) -> Dict[str, Any]:
        # full status of all our models
        installed_models = self.get_installed_models()
        recommended_models = self.get_recommended_models()
        
        # figure out which recommended ones we actually have
        installed_names = [m['name'] for m in installed_models]
        for model in recommended_models:
            model['installed'] = model['name'] in installed_names
            model['status'] = 'installed' if model['installed'] else 'available'
        
        current_model = self.config.OLLAMA_MODEL
        current_model_info = None
        
        # get details on what we're currently using
        for model in installed_models:
            if model['name'] == current_model or model['name'].startswith(current_model.split(':')[0]):
                current_model_info = model
                break
        
        return {
            'ollama_available': self.is_ollama_available(),
            'ollama_host': self.config.OLLAMA_HOST,
            'current_model': current_model,
            'current_model_info': current_model_info,
            'installed_models': installed_models,
            'recommended_models': recommended_models,
            'total_installed': len(installed_models),
            'total_recommended': len(recommended_models)
        }
    
    def pull_model(self, model_name: str) -> Dict[str, Any]:
        # download a model from ollama
        if not self.is_ollama_available():
            return {'success': False, 'error': 'Ollama not available'}
        
        try:
            logger.info(f"Starting pull for model: {model_name}")
            
            # kick off the download
            pull_response = self.client.pull(model_name)
            
            return {
                'success': True,
                'message': f'Successfully pulled model {model_name}',
                'model_name': model_name
            }
            
        except Exception as e:
            logger.error(f"Error pulling model {model_name}: {e}")
            return {
                'success': False,
                'error': f'Failed to pull model {model_name}: {str(e)}',
                'model_name': model_name
            }
    
    def delete_model(self, model_name: str) -> Dict[str, Any]:
        # remove a model we don't need
        if not self.is_ollama_available():
            return {'success': False, 'error': 'Ollama not available'}
        
        try:
            self.client.delete(model_name)
            
            return {
                'success': True,
                'message': f'Successfully deleted model {model_name}',
                'model_name': model_name
            }
            
        except Exception as e:
            logger.error(f"Error deleting model {model_name}: {e}")
            return {
                'success': False,
                'error': f'Failed to delete model {model_name}: {str(e)}',
                'model_name': model_name
            }
    
    def test_model(self, model_name: str) -> Dict[str, Any]:
        # quick test to see if model works
        if not self.is_ollama_available():
            return {'success': False, 'error': 'Ollama not available'}
        
        try:
            test_prompt = "Respond with 'OK' if you can process this message."
            
            response = self.client.chat(
                model=model_name,
                messages=[{'role': 'user', 'content': test_prompt}],
                options={'num_predict': 10}
            )
            
            response_text = response['message']['content'].strip()
            
            return {
                'success': True,
                'message': f'Model {model_name} is working correctly',
                'response': response_text,
                'model_name': model_name
            }
            
        except Exception as e:
            logger.error(f"Error testing model {model_name}: {e}")
            return {
                'success': False,
                'error': f'Model test failed: {str(e)}',
                'model_name': model_name
            }
    
    def set_active_model(self, model_name: str) -> Dict[str, Any]:
        # switch to using a different model
        try:
            # make sure the model is actually installed
            installed_models = self.get_installed_models()
            model_exists = any(m['name'] == model_name for m in installed_models)
            
            if not model_exists:
                return {
                    'success': False,
                    'error': f'Model {model_name} is not installed'
                }
            
            # check that it actually works
            test_result = self.test_model(model_name)
            if not test_result['success']:
                return {
                    'success': False,
                    'error': f'Model {model_name} failed test: {test_result["error"]}'
                }
            
            # change the active model (only for this session)
            self.config.OLLAMA_MODEL = model_name
            
            return {
                'success': True,
                'message': f'Active model set to {model_name}',
                'model_name': model_name
            }
            
        except Exception as e:
            logger.error(f"Error setting active model {model_name}: {e}")
            return {
                'success': False,
                'error': f'Failed to set active model: {str(e)}'
            }
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        # full details on a particular model
        installed_models = self.get_installed_models()
        
        for model in installed_models:
            if model['name'] == model_name:
                return model
        
        # see if this is one of our recommended ones
        for model in self.recommended_models:
            if model['name'] == model_name:
                model_info = model.copy()
                model_info['installed'] = False
                model_info['status'] = 'available'
                return model_info
        
        return None
    
    def format_model_size(self, size_bytes: int) -> str:
        # make file sizes readable (MB/GB)
        if size_bytes < 1024**3:
            return f"{size_bytes / (1024**2):.1f} MB"
        else:
            return f"{size_bytes / (1024**3):.1f} GB"