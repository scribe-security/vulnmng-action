"""Enhancer registry for managing multiple enrichment sources."""
import logging
from typing import List, Dict, Any
from vulnmng.core.interfaces import EnhancerBase
from vulnmng.plugins.enhancers.cisa_enrichment import CisaEnrichment

logger = logging.getLogger(__name__)


class EnhancerRegistry:
    """Registry for managing available enhancers."""
    
    _enhancers = {
        "cisa": CisaEnrichment,
    }
    
    @classmethod
    def get_enhancers(cls, enrichment_list: List[str]) -> List[EnhancerBase]:
        """Get a list of enhancer instances based on enrichment names.
        
        Args:
            enrichment_list: List of enrichment names (e.g., ['cisa'])
            
        Returns:
            List of instantiated enhancers in the order specified
            
        Raises:
            ValueError: If an unknown enrichment name is provided
        """
        enhancers = []
        for name in enrichment_list:
            name_lower = name.lower()
            if name_lower not in cls._enhancers:
                raise ValueError(f"Unknown enrichment: {name}. Available: {', '.join(cls._enhancers.keys())}")
            enhancers.append(cls._enhancers[name_lower]())
        return enhancers
    
    @classmethod
    def available_enrichments(cls) -> List[str]:
        """Get list of available enrichment names."""
        return list(cls._enhancers.keys())
