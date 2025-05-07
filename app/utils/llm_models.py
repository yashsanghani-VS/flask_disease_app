from datetime import datetime
from typing import Dict, Any, Optional, Union, List
import json
import base64
from PIL import Image
import io
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.output_parsers import StrOutputParser, JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from app.config import Config
from app.utils.prompts import PromptTemplates

logger = logging.getLogger(__name__)

class ModelError(Exception):
    """Base exception for model-related errors."""
    pass

class ModelResponseError(ModelError):
    """Exception for invalid model responses."""
    pass

class ModelHandler:
    """Advanced handler for different AI models using LangChain."""

    def __init__(self, api_keys: Dict[str, str]):
        """Initialize LangChain model handlers with API keys."""
        self._validate_api_keys(api_keys)
        
        # Initialize LangChain model instances
        self.gpt4_vision = self._create_gpt4_model(api_keys)
        self.gemini_vision = self._create_gemini_model(api_keys)
        self.groq_llm = self._create_groq_model(api_keys)

        # Initialize fallback models
        self.fallback_models = {
            "gpt4": self._create_gpt4_fallback_model(api_keys),
            "gemini": self._create_gemini_fallback_model(api_keys),
            "groq": self._create_groq_fallback_model(api_keys)
        }

        # Set up the output parsers
        self.json_parser = JsonOutputParser()
        self.structured_parser = self._create_output_parser()

    def _validate_api_keys(self, api_keys: Dict[str, str]) -> None:
        """Validate API keys."""
        required_keys = ["OPENAI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY"]
        missing_keys = [key for key in required_keys if not api_keys.get(key)]
        if missing_keys:
            raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")

    def _create_gpt4_model(self, api_keys: Dict[str, str]) -> ChatOpenAI:
        """Create GPT-4 model instance."""
        return ChatOpenAI(
            model=Config.GPT4_MODEL,
            api_key=api_keys.get("OPENAI_API_KEY"),
            temperature=0,
            max_tokens=4096,
            model_kwargs={"response_format": {"type": "json_object"}},
            timeout=Config.MODEL_PARAMS["gpt4"]["timeout"]
        )

    def _create_gemini_model(self, api_keys: Dict[str, str]) -> ChatGoogleGenerativeAI:
        """Create Gemini model instance."""
        return ChatGoogleGenerativeAI(
            model=Config.GEMINI_MODEL,
            google_api_key=api_keys.get("GOOGLE_API_KEY"),
            temperature=0,
            max_output_tokens=Config.MODEL_PARAMS["gemini"]["max_output_tokens"],
            top_p=0.8,
            top_k=40,
            timeout=Config.MODEL_PARAMS["gemini"]["timeout"],
            safety_settings={
                0: 0,  # HARM_CATEGORY_HARASSMENT: BLOCK_NONE
                1: 0,  # HARM_CATEGORY_HATE_SPEECH: BLOCK_NONE
                2: 0,  # HARM_CATEGORY_SEXUALLY_EXPLICIT: BLOCK_NONE
                3: 0   # HARM_CATEGORY_DANGEROUS_CONTENT: BLOCK_NONE
            }
        )

    def _create_groq_model(self, api_keys: Dict[str, str]) -> ChatGroq:
        """Create Groq model instance."""
        return ChatGroq(
            model_name=Config.GROQ_MODEL,
            api_key=api_keys.get("GROQ_API_KEY"),
            temperature=0,
            max_tokens=Config.MODEL_PARAMS["groq"]["max_tokens"],
            model_kwargs={"top_p": 0.8},
            timeout=Config.MODEL_PARAMS["groq"]["timeout"]
        )

    def _create_gpt4_fallback_model(self, api_keys: Dict[str, str]) -> ChatOpenAI:
        """Create GPT-4 fallback model instance."""
        return ChatOpenAI(
            model=Config.FALLBACK_MODELS["gpt4"],
            api_key=api_keys.get("OPENAI_API_KEY"),
            temperature=0,
            max_tokens=4096,
            model_kwargs={"response_format": {"type": "json_object"}},
            timeout=Config.MODEL_PARAMS["gpt4"]["timeout"]
        )

    def _create_gemini_fallback_model(self, api_keys: Dict[str, str]) -> ChatGoogleGenerativeAI:
        """Create Gemini fallback model instance."""
        return ChatGoogleGenerativeAI(
            model=Config.FALLBACK_MODELS["gemini"],
            google_api_key=api_keys.get("GOOGLE_API_KEY"),
            temperature=0,
            max_output_tokens=Config.MODEL_PARAMS["gemini"]["max_output_tokens"],
            top_p=0.8,
            top_k=40,
            timeout=Config.MODEL_PARAMS["gemini"]["timeout"]
        )

    def _create_groq_fallback_model(self, api_keys: Dict[str, str]) -> ChatGroq:
        """Create Groq fallback model instance."""
        return ChatGroq(
            model_name=Config.FALLBACK_MODELS["groq"],
            api_key=api_keys.get("GROQ_API_KEY"),
            temperature=0,
            max_tokens=Config.MODEL_PARAMS["groq"]["max_tokens"],
            model_kwargs={"top_p": 0.8},
            timeout=Config.MODEL_PARAMS["groq"]["timeout"]
        )

    # @retry(
    #     stop=stop_after_attempt(3),
    #     wait=wait_exponential(multiplier=1, min=4, max=10),
    #     retry=retry_if_exception_type((ModelError, Exception))
    # )
    def _invoke_model(self, model: Any, messages: List[Any]) -> Any:
        """Invoke model with retry logic."""
        try:
            return model.invoke(messages)
        except Exception as e:
            logger.error(f"Model invocation error: {str(e)}")
            raise ModelError(f"Failed to invoke model: {str(e)}")

    def process_image(self, image_data: str) -> Dict[str, Any]:
        """Process and validate image data, returning image bytes and metadata."""
        try:
            # Handle base64 image data
            if isinstance(image_data, str):
                if image_data.startswith("data:image"):
                    # Extract the base64 part after the comma
                    image_data = image_data.split(",")[1]
                try:
                    image_bytes = base64.b64decode(image_data)
                except Exception as e:
                    raise ValueError(f"Invalid base64 image data: {str(e)}")
            else:
                raise ValueError("Image data must be a string")

            # Validate image and get metadata
            try:
                image = Image.open(io.BytesIO(image_bytes))
                # Optimize image if needed
                if image.format in ["JPEG", "JPG"]:
                    output = io.BytesIO()
                    image.save(output, format="JPEG", quality=Config.IMAGE_QUALITY)
                    image_bytes = output.getvalue()
                
                metadata = {
                    "format": image.format,
                    "mode": image.mode,
                    "size": image.size,
                    "processed_at": datetime.utcnow().isoformat(),
                }
                image.close()
            except Exception as e:
                raise ValueError(f"Invalid or corrupted image: {str(e)}")

            return {
                "bytes": image_bytes,
                "base64": image_data,
                "metadata": metadata
            }
        except Exception as e:
            logger.error(f"Image processing error: {str(e)}")
            raise ValueError(f"Image processing failed: {str(e)}")

    def _create_output_parser(self) -> StructuredOutputParser:
        """Create a structured output parser for model responses."""
        response_schemas = [
            ResponseSchema(
                name="plant_info",
                description="Information about the plant including species, health status, and characteristics",
                type="object"
            ),
            ResponseSchema(
                name="disease_info",
                description="Information about the disease including name, symptoms, and severity",
                type="object"
            ),
            ResponseSchema(
                name="treatment",
                description="Treatment recommendations including methods, products, and application instructions",
                type="object"
            ),
            ResponseSchema(
                name="prevention",
                description="Prevention measures to avoid future disease outbreaks",
                type="object"
            ),
            ResponseSchema(
                name="additional_info",
                description="Additional information about the diagnosis and recommendations",
                type="object"
            )
        ]
        return StructuredOutputParser.from_response_schemas(response_schemas)

    # @retry(
    #     stop=stop_after_attempt(3),
    #     wait=wait_exponential(multiplier=1, min=4, max=10),
    #     retry=retry_if_exception_type((ModelError, Exception))
    # )
    def analyze_with_gpt4(
        self, image_data: Dict[str, Any], symptoms: str, region: str, crop_type: str
    ) -> Dict[str, Any]:
        """Analyze plant using GPT-4 with LangChain."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gpt4_prompt(
                region=region,
                crop_type=crop_type,
                symptoms=symptoms,
                image_data=image_data['base64']
            )

            # Create messages for GPT-4
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"])
            ]

            try:
                response = self._invoke_model(self.gpt4_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary GPT-4 model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gpt4"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gpt4_vision")
        except Exception as e:
            logger.error(f"GPT-4 analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with GPT-4: {str(e)}")

    # @retry(
    #     stop=stop_after_attempt(3),
    #     wait=wait_exponential(multiplier=1, min=4, max=10),
    #     retry=retry_if_exception_type((ModelError, Exception))
    # )
    def analyze_with_gemini(
        self, image_data: Dict[str, Any], symptoms: str, region: str, crop_type: str
    ) -> Dict[str, Any]:
        """Analyze plant using Gemini with LangChain."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gemini_prompt(
                region=region,
                crop_type=crop_type,
                symptoms=symptoms,
                image_data=image_data['base64']
            )

            # Create messages for Gemini
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"])
            ]

            try:
                response = self._invoke_model(self.gemini_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary Gemini model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gemini"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gemini_vision")
        except Exception as e:
            logger.error(f"Gemini analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with Gemini: {str(e)}")

    # @retry(
    #     stop=stop_after_attempt(3),
    #     wait=wait_exponential(multiplier=1, min=4, max=10),
    #     retry=retry_if_exception_type((ModelError, Exception))
    # )
    def analyze_with_groq(
        self, symptoms: str, region: str, crop_type: str
    ) -> Dict[str, Any]:
        """Analyze plant using Groq with LangChain."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_groq_prompt(
                region=region,
                crop_type=crop_type,
                symptoms=symptoms
            )

            # Create messages for Groq
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"])
            ]

            try:
                response = self._invoke_model(self.groq_llm, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary Groq model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["groq"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "groq")
        except Exception as e:
            logger.error(f"Groq analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with Groq: {str(e)}")

    def _parse_response(self, content: str) -> Dict[str, Any]:
        """Parse and validate model response."""
        try:
            # Clean the content of any markdown formatting
            content = content.strip()
            if content.startswith('```'):
                content = content.split('\n', 1)[1]
            if content.endswith('```'):
                content = content.rsplit('\n', 1)[0]
            content = content.strip()

            # Try to parse as JSON
            try:
                result = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {str(e)}")
                raise ModelResponseError(f"Invalid JSON format: {str(e)}")

            # Validate required fields
            required_fields = ["plant_info", "disease_info", "treatment", "prevention", "additional_info", "user_guidance"]
            missing_fields = [field for field in required_fields if field not in result]
            if missing_fields:
                raise ModelResponseError(f"Missing required fields: {', '.join(missing_fields)}")

            # Validate and set default values for confidence scores
            if "confidence" not in result["plant_info"]:
                result["plant_info"]["confidence"] = 0.85
            if "confidence" not in result["disease_info"]:
                result["disease_info"]["confidence"] = 0.80

            # Ensure arrays are actually arrays
            for field in ["symptoms", "methods", "products", "measures", "best_practices", "references", "follow_up_questions"]:
                if field in result["disease_info"] and not isinstance(result["disease_info"][field], list):
                    result["disease_info"][field] = [result["disease_info"][field]]
                if field in result["treatment"] and not isinstance(result["treatment"][field], list):
                    result["treatment"][field] = [result["treatment"][field]]
                if field in result["prevention"] and not isinstance(result["prevention"][field], list):
                    result["prevention"][field] = [result["prevention"][field]]
                if field in result["additional_info"] and not isinstance(result["additional_info"][field], list):
                    result["additional_info"][field] = [result["additional_info"][field]]
                if field in result["user_guidance"] and not isinstance(result["user_guidance"][field], list):
                    result["user_guidance"][field] = [result["user_guidance"][field]]

            # Validate and set default values for plant_info
            if "is_plant_image" not in result["plant_info"]:
                result["plant_info"]["is_plant_image"] = True
            if "image_quality" not in result["plant_info"]:
                result["plant_info"]["image_quality"] = "Good"
            if "image_feedback" not in result["plant_info"]:
                result["plant_info"]["image_feedback"] = "Image appears to be of a plant or leaf."

            # Validate and set default values for disease_info
            if "analysis_type" not in result["disease_info"]:
                result["disease_info"]["analysis_type"] = "Image-based"

            # Validate and set default values for user_guidance
            if "image_improvement" not in result["user_guidance"]:
                result["user_guidance"]["image_improvement"] = "No specific improvements needed."
            if "additional_info_needed" not in result["user_guidance"]:
                result["user_guidance"]["additional_info_needed"] = "No additional information needed."
            if "follow_up_questions" not in result["user_guidance"]:
                result["user_guidance"]["follow_up_questions"] = []

            return result
        except Exception as e:
            logger.error(f"Response parsing error: {str(e)}")
            raise ModelResponseError(f"Failed to parse model response: {str(e)}")

    def _enhance_result(
        self, result: Dict[str, Any], model_name: str
    ) -> Dict[str, Any]:
        """Enhance the analysis result with additional metadata."""
        try:
            # Add metadata
            result["metadata"] = {
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "model_name": model_name,
                "model_version": "2.0",
                "confidence_score": self._calculate_confidence_score(result),
                "analysis_type": result["disease_info"].get("analysis_type", "Image-based"),
                "has_symptoms": bool(result.get("symptoms", "")),
                "image_quality": result["plant_info"].get("image_quality", "Good"),
                "is_plant_image": result["plant_info"].get("is_plant_image", True)
            }

            # Add user guidance based on the analysis
            if not result["plant_info"]["is_plant_image"]:
                result["user_guidance"]["image_improvement"] = "Please upload an image of a plant or leaf for better analysis."
            elif result["plant_info"]["image_quality"] != "Good":
                result["user_guidance"]["image_improvement"] = f"Please try to take a clearer image. {result['plant_info']['image_feedback']}"
            
            if not result.get("symptoms", ""):
                result["user_guidance"]["additional_info_needed"] = "Please provide any symptoms or observations you've noticed about the plant."

            return result
        except Exception as e:
            logger.error(f"Result enhancement error: {str(e)}")
            raise ModelError(f"Failed to enhance result: {str(e)}")

    def _calculate_confidence_score(self, result: Dict[str, Any]) -> float:
        """Calculate improved confidence score."""
        try:
            plant_conf = float(result.get("plant_info", {}).get("confidence", 0))
            disease_conf = float(result.get("disease_info", {}).get("confidence", 0))
            
            image_quality = result["plant_info"].get("image_quality", "Good")
            is_plant = result["plant_info"].get("is_plant_image", True)
            
            quality_factor = {
                "Good": 1.0,
                "Medium": 0.9,
                "Poor": 0.7
            }.get(image_quality, 0.6)

            if not is_plant:
                quality_factor *= 0.6
            
            base_score = (plant_conf * 0.5 + disease_conf * 0.5)
            
            if plant_conf > 0.85 and disease_conf > 0.85:
                quality_factor = max(quality_factor, 0.95)
            
            return round(base_score * quality_factor, 3)
        except Exception as e:
            logger.error(f"Confidence calculation error: {str(e)}")
            return 0.6

    def get_multi_model_analysis(
        self, image_data: str, symptoms: str, region: str, crop_type: str
    ) -> Dict[str, Any]:
        """Perform analysis using multiple models and combine results."""
        try:
            processed_image = self.process_image(image_data)
            results = {}

            # Try each model and collect successful results
            for model_name, analyzer in [
                ("gpt4", self.analyze_with_gpt4),
                ("gemini", self.analyze_with_gemini),
                ("groq", lambda s, r, c: self.analyze_with_groq(s, r, c))
            ]:
                try:
                    if model_name == "groq":
                        results[model_name] = analyzer(symptoms, region, crop_type)
                    else:
                        results[model_name] = analyzer(processed_image, symptoms, region, crop_type)
                except Exception as e:
                    logger.warning(f"{model_name} analysis failed: {str(e)}")
                    continue

            if not results:
                raise ModelError("All models failed to analyze the input")

            # Find the best result
            best_model = max(
                results.items(),
                key=lambda x: x[1]["metadata"]["confidence_score"]
            )

            result = best_model[1]
            result["metadata"]["comparison"] = {
                "models_used": list(results.keys()),
                "best_model": best_model[0],
                "confidence_scores": {
                    model: data["metadata"]["confidence_score"]
                    for model, data in results.items()
                },
            }

            return result
        except Exception as e:
            logger.error(f"Multi-model analysis error: {str(e)}")
            raise ModelError(f"Failed to perform multi-model analysis: {str(e)}")

    def analyze_with_gpt4_text(self, symptoms: str, region: str, crop_type: str) -> Dict[str, Any]:
        """Analyze plant using GPT-4 with text-only input."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gpt4_prompt(
                region=region,
                crop_type=crop_type,
                symptoms=symptoms,
                query_type="text_only"
            )

            # Create messages for GPT-4
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"][0]["text"])
            ]

            try:
                response = self._invoke_model(self.gpt4_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary GPT-4 model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gpt4"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gpt4_vision")
        except Exception as e:
            logger.error(f"GPT-4 text analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with GPT-4: {str(e)}")

    def analyze_with_gpt4_image(self, image_data: Dict[str, Any], region: str, crop_type: str) -> Dict[str, Any]:
        """Analyze plant using GPT-4 with image-only input."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gpt4_prompt(
                region=region,
                crop_type=crop_type,
                symptoms="",
                image_data=image_data['base64'],
                query_type="image_only"
            )

            # Create messages for GPT-4
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"][0]["text"]),
                HumanMessage(content=prompt_template["human"][1])
            ]

            try:
                response = self._invoke_model(self.gpt4_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary GPT-4 model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gpt4"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gpt4_vision")
        except Exception as e:
            logger.error(f"GPT-4 image analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with GPT-4: {str(e)}")

    def analyze_with_gemini_text(self, symptoms: str, region: str, crop_type: str) -> Dict[str, Any]:
        """Analyze plant using Gemini with text-only input."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gemini_prompt(
                region=region,
                crop_type=crop_type,
                symptoms=symptoms,
                query_type="text_only"
            )

            # Create messages for Gemini
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"][0])
            ]

            try:
                response = self._invoke_model(self.gemini_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary Gemini model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gemini"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gemini_vision")
        except Exception as e:
            logger.error(f"Gemini text analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with Gemini: {str(e)}")

    def analyze_with_gemini_image(self, image_data: Dict[str, Any], region: str, crop_type: str) -> Dict[str, Any]:
        """Analyze plant using Gemini with image-only input."""
        try:
            # Get prompt template
            prompt_template = PromptTemplates.get_gemini_prompt(
                region=region,
                crop_type=crop_type,
                symptoms="",
                image_data=image_data['base64'],
                query_type="image_only"
            )

            # Create messages for Gemini
            messages = [
                SystemMessage(content=prompt_template["system"]),
                HumanMessage(content=prompt_template["human"][0]),
                HumanMessage(content=prompt_template["human"][1])
            ]

            try:
                response = self._invoke_model(self.gemini_vision, messages)
                result = self._parse_response(response.content)
            except Exception as e:
                logger.warning(f"Primary Gemini model failed, trying fallback: {str(e)}")
                response = self._invoke_model(self.fallback_models["gemini"], messages)
                result = self._parse_response(response.content)

            return self._enhance_result(result, "gemini_vision")
        except Exception as e:
            logger.error(f"Gemini image analysis error: {str(e)}")
            raise ModelError(f"Failed to analyze with Gemini: {str(e)}")
