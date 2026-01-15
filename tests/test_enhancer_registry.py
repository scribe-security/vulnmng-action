import unittest
from vulnmng.plugins.enhancers.registry import EnhancerRegistry
from vulnmng.plugins.enhancers.cisa_enrichment import CisaEnrichment


class TestEnhancerRegistry(unittest.TestCase):
    def test_get_enhancers_single(self):
        enhancers = EnhancerRegistry.get_enhancers(['cisa'])
        self.assertEqual(len(enhancers), 1)
        self.assertIsInstance(enhancers[0], CisaEnrichment)
    
    def test_get_enhancers_case_insensitive(self):
        enhancers = EnhancerRegistry.get_enhancers(['CISA'])
        self.assertEqual(len(enhancers), 1)
        self.assertIsInstance(enhancers[0], CisaEnrichment)
    
    def test_get_enhancers_unknown(self):
        with self.assertRaises(ValueError) as context:
            EnhancerRegistry.get_enhancers(['unknown'])
        self.assertIn('Unknown enrichment: unknown', str(context.exception))
    
    def test_available_enrichments(self):
        available = EnhancerRegistry.available_enrichments()
        self.assertIn('cisa', available)
        self.assertIsInstance(available, list)


if __name__ == '__main__':
    unittest.main()
