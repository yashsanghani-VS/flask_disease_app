"""This module contains all the prompts used for different AI models in the plant disease diagnosis system."""

from typing import Dict

class SystemPrompts:
    """Class containing system prompts for different models."""
    
    @staticmethod
    def get_base_system_prompt() -> str:
        """Get the base system prompt used across all models."""
        return """
            You are a friendly and knowledgeable plant disease diagnosis expert. Your task is to analyze plant images and provide helpful guidance.

            IMPORTANT: You MUST respond with a valid JSON object EXACTLY matching this structure:
            {
            "plant_info": {
                "species": "Scientific name of the plant",
                "common_name": "Common name of the plant",
                "health_status": "Overall health status",
                "confidence": 0.95,
                "is_plant_image": true,
                "image_quality": "Good/Medium/Poor",
                "image_feedback": "Feedback about the image quality and content"
            },
            "disease_info": {
                "name": "Name of the disease if present",
                "symptoms": ["List", "of", "observed", "symptoms"],
                "severity": "Severity level (Low/Medium/High)",
                "confidence": 0.91,
                "analysis_type": "Image-based/Text-based/Combined"
            },
            "treatment": {
                "methods": ["List", "of", "recommended", "treatment", "methods"],
                "products": ["List", "of", "recommended", "products"],
                "instructions": "Detailed application instructions"
            },
            "prevention": {
                "measures": ["List", "of", "prevention", "measures"],
                "best_practices": ["List", "of", "best", "practices"]
            },
            "additional_info": {
                "notes": "Additional important information",
                "references": ["List", "of", "reference", "sources"],
                "recommendations": ["List", "of", "general", "recommendations"],
                "next_steps": ["List", "of", "suggested", "next", "steps"]
            },
            "user_guidance": {
                "image_improvement": "Suggestions for better image capture",
                "additional_info_needed": "What additional information would help",
                "follow_up_questions": ["List", "of", "relevant", "questions"]
            },
            "query_type": "Image-based/Text-based/Combined",
            "query_intent": "Disease detection/General information/Question answering",
            "response_focus": "What the response should focus on"
            }

            CRITICAL REQUIREMENTS:
            1. Your response MUST be a single JSON object with EXACTLY these top-level keys
            2. DO NOT include any other top-level keys
            3. DO NOT wrap the JSON in markdown code blocks or any other formatting
            4. Each field must contain the specified sub-fields
            5. Confidence scores must be numbers between 0 and 1
            6. Arrays must be actual JSON arrays, not strings
            7. Do not include any explanatory text before or after the JSON
            8. If the image is not of a plant or leaf, set is_plant_image to false and provide appropriate feedback
            9. If symptoms are missing, provide general guidance based on the image or request more information
            10. Always provide helpful user guidance for better diagnosis
            11. For text-only queries, focus on providing general information about plants
            12. For image-only queries, analyze the image and provide relevant information
            13. For general questions, provide accurate and helpful answers
            14. Always maintain a friendly and helpful tone
        """

class HumanPrompts:
    """Class containing human prompts for different models."""
    
    @staticmethod
    def get_analysis_prompt(region: str, crop_type: str, symptoms: str, query_type: str = "combined") -> str:
        """Get the analysis prompt with region, crop type, and symptoms."""
        base_prompt = f"""
            Please analyze this plant-related query:
            Region: {region}
            Crop Type: {crop_type}
        """
        
        if query_type == "text_only":
            base_prompt += f"\nUser Query: {symptoms}"
            base_prompt += "\n\nPlease provide information about the plant or answer the question in the exact JSON structure specified above."
        elif query_type == "image_only":
            base_prompt += "\nNote: No specific symptoms were provided. Please analyze the image and provide relevant information about the plant."
        else:
            if symptoms and symptoms.strip():
                base_prompt += f"\nSymptoms/Observations: {symptoms}"
            else:
                base_prompt += "\nNote: No specific symptoms were provided. Please provide general guidance based on the image or request more information."
            
        base_prompt += "\n\nPlease provide your analysis in the exact JSON structure specified above. If the image is not of a plant or leaf, please indicate this and provide appropriate guidance."
        
        return base_prompt

class PromptTemplates:
    """Class containing prompt templates for different models."""
    
    @staticmethod
    def get_gpt4_prompt(region: str, crop_type: str, symptoms: str, image_data: str = None, query_type: str = "combined") -> Dict:
        """Get the complete prompt template for GPT-4."""
        if query_type == "text_only":
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    {"type": "text", "text": HumanPrompts.get_analysis_prompt(region, crop_type, symptoms, "text_only")}
                ]
            }
        elif query_type == "image_only":
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    {"type": "text", "text": HumanPrompts.get_analysis_prompt(region, crop_type, "", "image_only")},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_data}"}
                    }
                ]
            }
        else:
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    {"type": "text", "text": HumanPrompts.get_analysis_prompt(region, crop_type, symptoms)},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_data}"}
                    }
                ]
            }
    
    @staticmethod
    def get_gemini_prompt(region: str, crop_type: str, symptoms: str, image_data: str = None, query_type: str = "combined") -> Dict:
        """Get the complete prompt template for Gemini."""
        if query_type == "text_only":
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    HumanPrompts.get_analysis_prompt(region, crop_type, symptoms, "text_only")
                ]
            }
        elif query_type == "image_only":
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    HumanPrompts.get_analysis_prompt(region, crop_type, "", "image_only"),
                    {
                        "type": "image_url",
                        "image_url": f"data:image/jpeg;base64,{image_data}"
                    }
                ]
            }
        else:
            return {
                "system": SystemPrompts.get_base_system_prompt(),
                "human": [
                    HumanPrompts.get_analysis_prompt(region, crop_type, symptoms),
                    {
                        "type": "image_url",
                        "image_url": f"data:image/jpeg;base64,{image_data}"
                    }
                ]
            }
    
    @staticmethod
    def get_groq_prompt(region: str, crop_type: str, symptoms: str, query_type: str = "text_only") -> Dict:
        """Get the complete prompt template for Groq."""
        return {
            "system": SystemPrompts.get_base_system_prompt(),
            "human": HumanPrompts.get_analysis_prompt(region, crop_type, symptoms, query_type)
        } 