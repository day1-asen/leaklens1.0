"""Model integration module for LFM2.5-1.2B-Thinking"""

import requests
import json

class LFModel:
    """LFM2.5-1.2B-Thinking model wrapper"""
    
    def __init__(self, model_name="lfm2.5-thinking:1.2b", use_ollama=True, model_path="./LFM2.5-1.2B-Thinking", use_quantization=False, device=None):
        """
        Initialize the LFM2.5-1.2B-Thinking model
        
        Args:
            model_name: Ollama model name
            use_ollama: Whether to use Ollama API
            model_path: Local path to the model directory (for non-Ollama mode)
            use_quantization: Whether to use 4-bit quantization (for non-Ollama mode)
            device: Device to use (e.g., "cuda", "cpu") (for non-Ollama mode)
        """
        self.model_name = model_name
        self.use_ollama = use_ollama
        self.model_path = model_path
        self.use_quantization = use_quantization
        self.device = device
        self.tokenizer = None
        self.model = None
        
        if self.use_ollama:
            print(f"Using Ollama model: {model_name}")
            self._test_ollama_connection()
        else:
            # 保持原有本地模型加载逻辑
            self._load_local_model()
    
    def _test_ollama_connection(self):
        """Test Ollama API connection"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_found = any(model["name"] == self.model_name for model in models)
                if not model_found:
                    raise RuntimeError(
                        f"Model {self.model_name} not found in Ollama.\n"
                        f"Please run: ollama pull {self.model_name}"
                    )
                print(f"Ollama model {self.model_name} found and ready!")
            else:
                raise RuntimeError(
                    f"Failed to connect to Ollama: {response.status_code}\n"
                    "Please ensure Ollama is running: ollama serve"
                )
        except Exception as e:
            raise RuntimeError(
                f"Failed to connect to Ollama: {str(e)}\n"
                "Please ensure Ollama is installed and running"
            ) from e
    
    def _load_local_model(self):
        """Load the model and tokenizer from local files"""
        import os
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        
        print(f"Loading model from {self.model_path} on {self.device}...")
        
        # Check if model directory exists
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model directory not found: {self.model_path}\n"
                "Please follow these steps to download and deploy the model:\n"
                "1. From official channel, download LFM2.5-1.2B-Thinking model files\n"
                "2. Extract the files to the project root directory\n"
                "3. Make sure the directory structure is: leaklens/LFM2.5-1.2B-Thinking/\n"
                "4. Ensure the directory contains config.json, model.safetensors, and tokenizer.json"
            )
        
        # Check if required files exist
        required_files = ["config.json", "model.safetensors", "tokenizer.json"]
        for file in required_files:
            file_path = os.path.join(self.model_path, file)
            if not os.path.exists(file_path):
                raise FileNotFoundError(
                    f"Missing required model file: {file}\n"
                    f"Please ensure all required files are present in {self.model_path}"
                )
        
        try:
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path, trust_remote_code=True)
            
            # Configure model loading
            model_kwargs = {
                "trust_remote_code": True,
                "dtype": torch.float16
            }
            
            # Use quantization if enabled
            if self.use_quantization:
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_use_double_quant=True
                )
                model_kwargs["quantization_config"] = quantization_config
                print("Using 4-bit quantization for model")
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                **model_kwargs
            ).to(self.device)
            
            print("Model loaded successfully!")
        except Exception as e:
            raise RuntimeError(
                f"Failed to load model: {str(e)}\n"
                "Please check the following:\n"
                "1. Model files are complete and valid\n"
                "2. Dependencies are installed correctly\n"
                "3. Sufficient memory is available"
            ) from e
    
    def generate(self, prompt, max_length=512, temperature=0.7):
        """
        Generate text from the model
        
        Args:
            prompt: Input prompt
            max_length: Maximum length of generated text
            temperature: Sampling temperature
            
        Returns:
            Generated text
        """
        if self.use_ollama:
            return self._generate_with_ollama(prompt, max_length, temperature)
        else:
            return self._generate_with_local_model(prompt, max_length, temperature)
    
    def _generate_with_ollama(self, prompt, max_length=512, temperature=0.7):
        """Generate text using Ollama API"""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "options": {
                    "temperature": temperature,
                    "max_tokens": max_length
                }
            }
            
            response = requests.post(
                "http://localhost:11434/api/generate",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                # Process streaming response
                full_response = ""
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        if "response" in data:
                            full_response += data["response"]
                        if data.get("done", False):
                            break
                return full_response
            else:
                raise RuntimeError(
                    f"Ollama API error: {response.status_code}\n"
                    f"Response: {response.text}"
                )
        except Exception as e:
            raise RuntimeError(
                f"Failed to generate text with Ollama: {str(e)}"
            ) from e
    
    def _generate_with_local_model(self, prompt, max_length=512, temperature=0.7):
        """Generate text using local model"""
        if not self.tokenizer or not self.model:
            raise ValueError("Model not loaded")
        
        # Format prompt for LFM2.5 Instruct
        messages = [
            {"role": "user", "content": prompt}
        ]
        
        # Tokenize input
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        # Generate response
        inputs = self.tokenizer([text], return_tensors="pt").to(self.device)
        outputs = self.model.generate(
            **inputs,
            max_new_tokens=max_length,
            temperature=temperature,
            top_p=0.95,
            repetition_penalty=1.1
        )
        
        # Decode response
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response

# Global model instance
lf_model = None

def get_lf_model(model_name="lfm2.5-thinking:1.2b", use_ollama=True, model_path="./LFM2.5-1.2B-Thinking", use_quantization=False, device=None):
    """
    Get the global LFM model instance
    
    Args:
        model_name: Ollama model name
        use_ollama: Whether to use Ollama API
        model_path: Local path to the model directory (for non-Ollama mode)
        use_quantization: Whether to use 4-bit quantization (for non-Ollama mode)
        device: Device to use (e.g., "cuda", "cpu") (for non-Ollama mode)
        
    Returns:
        LFModel instance
    """
    global lf_model
    if lf_model is None:
        lf_model = LFModel(model_name, use_ollama, model_path, use_quantization, device)
    return lf_model

def generate_text(prompt, max_length=512, temperature=0.7):
    """
    Generate text using the LFM model
    
    Args:
        prompt: Input prompt
        max_length: Maximum length of generated text
        temperature: Sampling temperature
        
    Returns:
        Generated text
    """
    model = get_lf_model()
    return model.generate(prompt, max_length, temperature)
