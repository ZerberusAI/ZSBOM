import requests
import logging
from typing import Dict, Any

class GChatNotifier:
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config['notifications']['gchat']['webhook_url']
        self.notification_level = config['notifications']['gchat']['notification_level']
        self.logger = logging.getLogger(__name__)

    def format_message(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format validation results for Google Chat card message"""
        return {
            "cards": [{
                "header": {
                    "title": "🔒 ZSBOM Security Scan Results",
                    "subtitle": "Dependency Validation Report",
                    "imageUrl": "https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png"
                },
                "sections": [
                    {
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": f"<b>CVE Issues:</b> {len(results['cve_issues'])}<br>"
                                           f"<b>Abandoned Packages:</b> {len(results['abandoned_packages'])}<br>"
                                           f"<b>Whitelist Applied:</b> {len(results.get('typosquatting_whitelist', []))}<br>"
                                           f"<b>Version Issues:</b> {len(results['version_issues'])}"
                                }
                            }
                        ]
                    },
                    {
                        "widgets": [
                            {
                                "buttons": [
                                    {
                                        "textButton": {
                                            "text": "VIEW FULL REPORT",
                                            "onClick": {
                                                "openLink": {
                                                    "url": "https://your-report-url.com"  # Replace with your report URL
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }]
        }

    def should_notify(self, results: Dict[str, Any]) -> bool:
        """Determine if notification should be sent based on level"""
        if self.notification_level == "none":
            return False
        if self.notification_level == "all":
            return True
        if self.notification_level == "critical":
            return any([
                len(results['cve_issues']) > 0,
                len(results['abandoned_packages']) > 0
            ])
        return False

    def send(self, results: Dict[str, Any]) -> bool:
        """Send notification to Google Chat"""
        if not self.webhook_url or not self.should_notify(results):
            return False

        try:
            message = self.format_message(results)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )
            response.raise_for_status()
            self.logger.info("✅ Google Chat notification sent successfully")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to send Google Chat notification: {e}")
            return False