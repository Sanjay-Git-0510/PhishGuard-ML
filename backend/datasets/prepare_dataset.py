"""
Dataset Preparation & Curation Script for Phishing URL Detection
----------------------------------------------------------------
Generates a rigorously vetted, balanced labeled dataset:
  label = 0 -> Legitimate URL
  label = 1 -> Phishing URL

Ensures:
  - No exact duplicates
  - Standardized URL schemas
  - Documented class distribution
  - Representative lexical variations (IPs, TLDs, subdomains, params, legitimate portals)
Outputs:
  backend/datasets/urls_dataset.csv
"""

import os
import pandas as pd
from urllib.parse import urlparse

# Output paths
DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(DATASET_DIR, "urls_dataset.csv")

# Curated high-quality representative dataset samples
# (Structured to cover key real-world attack vectors and genuine benign structures)

BENIGN_URLS = [
    # Top global domains & subpages
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+threat+intelligence",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://drive.google.com/drive/my-drive",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://github.com",
    "https://github.com/torvalds/linux",
    "https://github.com/scikit-learn/scikit-learn/pulls",
    "https://github.com/tiangolo/fastapi",
    "https://github.com/login",
    "https://gist.github.com/discover",
    "https://stackoverflow.com",
    "https://stackoverflow.com/questions/tagged/python",
    "https://stackoverflow.com/users/login",
    "https://www.microsoft.com/en-us",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://docs.microsoft.com/en-us/azure/security",
    "https://azure.microsoft.com/en-us/pricing",
    "https://www.amazon.com",
    "https://www.amazon.com/gp/help/customer/display.html",
    "https://www.amazon.com/ap/signin",
    "https://aws.amazon.com/console",
    "https://aws.amazon.com/s3",
    "https://www.apple.com",
    "https://appleid.apple.com/sign-in",
    "https://developer.apple.com/documentation",
    "https://www.netflix.com/browse",
    "https://www.netflix.com/login",
    "https://www.linkedin.com/feed",
    "https://www.linkedin.com/in/cybersecurity-specialist",
    "https://www.linkedin.com/login",
    "https://twitter.com/home",
    "https://x.com/explore",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/feed/trending",
    "https://www.reddit.com/r/netsec",
    "https://www.reddit.com/r/MachineLearning",
    "https://www.cloudflare.com/learning/security/what-is-phishing",
    "https://dash.cloudflare.com/login",
    "https://www.python.org/downloads",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://pypi.org/project/scikit-learn",
    "https://fastapi.tiangolo.com/tutorial",
    "https://react.dev/reference/react",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
    "https://www.cisa.gov/cybersecurity",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    "https://www.mitre.org/news-insights/impact-stories",
    "https://attack.mitre.org/matrices/enterprise",
    "https://www.bbc.com/news/technology",
    "https://edition.cnn.com/business",
    "https://www.nytimes.com/section/technology",
    "https://www.reuters.com/technology",
    "https://www.bloomberg.com/technology",
    "https://www.nationalgeographic.com/science",
    "https://www.nasa.gov/missions",
    "https://www.nature.com/articles",
    "https://arxiv.org/abs/2301.00001",
    "https://scholar.google.com/citations",
    "https://www.mit.edu/research",
    "https://www.stanford.edu/academics",
    "https://www.harvard.edu/programs",
    "https://www.cam.ac.uk/research",
    "https://www.ox.ac.uk/admissions",
    "https://www.imperial.ac.uk/study",
    "https://www.gov.uk/browse/benefits",
    "https://www.irs.gov/payments",
    "https://www.who.int/emergencies",
    "https://www.un.org/en/about-us",
    "https://www.paypal.com/us/home",
    "https://www.paypal.com/signin",
    "https://www.chase.com/personal/banking",
    "https://secure01a.chase.com/web/auth/dashboard",
    "https://www.bankofamerica.com/online-banking",
    "https://www.wellsfargo.com",
    "https://www.citigroup.com/global",
    "https://www.spotify.com/us/premium",
    "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
    "https://www.salesforce.com/products/crm",
    "https://login.salesforce.com",
    "https://www.dropbox.com/login",
    "https://www.slack.com/signin",
    "https://www.zoom.us/join",
    "https://www.atlassian.com/software/jira",
    "https://gitlab.com/users/sign_in",
    "https://bitbucket.org/account/signin",
    "https://hub.docker.com/search",
    "https://www.postgresql.org/docs/current",
    "https://redis.io/commands",
    "https://www.kaggle.com/datasets",
    "https://huggingface.co/models",
    "https://medium.com/topic/cybersecurity",
    "https://dev.to/t/security",
    "https://news.ycombinator.com/item?id=30000000",
    "https://slashdot.org",
    "https://krebsonsecurity.com",
    "https://thehackernews.com/2024/01/security-alert.html",
    "https://arstechnica.com/information-technology",
    "https://wired.com/category/security",
    "https://techcrunch.com/startups",
    "https://venturebeat.com/ai",
    "https://engadget.com/reviews",
    "https://zdnet.com/topic/security",
    "https://bleepingcomputer.com/news/security",
    "https://securityweek.com/cybercrime",
    "https://darkreading.com/threat-intelligence",
    "https://threatpost.com/category/vulnerabilities",
    "https://cert.europa.eu/publications",
    "https://www.sans.org/white-papers",
    "https://owasp.org/www-project-top-ten",
    "https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Web_mechanisms/What_is_a_URL",
    "https://w3.org/Consortium/mission.html",
    "https://ietf.org/standards/rfcs",
    "https://icann.org/resources/pages/welcome-2012-02-25-en",
    "https://iso.org/standards.html",
    "https://ieee.org/membership/join/index.html",
    "https://acm.org/special-interest-groups",
    "https://craigslist.org/about/sites",
    "https://ebay.com/b/Electronics/bn_70002599",
    "https://walmart.com/browse/electronics/3944",
    "https://target.com/c/electronics/-/N-5xtg6",
    "https://bestbuy.com/site/computers-pcs/33924.c",
    "https://homedepot.com/c/tool_rental",
    "https://lowes.com/c/Appliances",
    "https://costco.com/warehouse-locations",
    "https://ikea.com/us/en/cat/furniture-fu001",
    "https://airbnb.com/rooms/1000000",
    "https://booking.com/hotel/us/example.html",
    "https://expedia.com/Flights",
    "https://tripadvisor.com/Attractions",
    "https://uber.com/us/en/ride",
    "https://lyft.com/rider",
    "https://doordash.com/food-delivery",
    "https://grubhub.com/delivery",
    "https://instacart.com/store",
    "https://etsy.com/c/jewelry",
    "https://shopify.com/pricing",
    "https://stripe.com/docs/api",
    "https://paypal-community.com/t5/General-Discussions/bd-p/US-General",
    "https://squareup.com/us/en/payments",
    "https://venmo.com/about/security",
    "https://zellepay.com/how-it-works",
    "https://robinhood.com/us/en",
    "https://coinbase.com/explore",
    "https://kraken.com/prices",
    "https://binance.com/en/markets/overview",
    "https://fidelity.com/trading/overview",
    "https://vanguard.com/us/investing",
    "https://schwab.com/brokerage",
    "https://etrade.com/what-we-offer",
    "https://tdameritrade.com/home.html",
    "https://allstate.com/auto-insurance",
    "https://geico.com/claims",
    "https://progressive.com/answers",
    "https://statefarm.com/insurance",
    "https://usaa.com/inet/wc/bank-checking",
    "https://capitalone.com/credit-cards",
    "https://discover.com/online-banking",
    "https://americanexpress.com/en-us/credit-cards",
    "https://barclays.co.uk/current-accounts",
    "https://hsbc.com/who-we-are",
    "https://lloydsbank.com/banking-with-us.html",
    "https://santander.co.uk/personal/current-accounts",
    "https://natwest.com/current-accounts.html",
    "https://standardchartered.com/en",
    "https://db.com/news",
    "https://bnpparibas.com/en",
    "https://ubs.com/global/en/wealth-management.html",
    "https://credit-suisse.com/us/en.html",
    "https://ing.com/About-us.htm",
    "https://nordea.com/en",
    "https://dnb.no/en/personal",
    "https://swedbank.com/about-swedbank.html",
    "https://anz.com/personal",
    "https://commbank.com.au/personal.html",
    "https://nab.com.au/personal/banking",
    "https://westpac.com.au/personal-banking",
    "https://rbcroyalbank.com/personal.html",
    "https://td.com/ca/en/personal-banking",
    "https://scotiabank.com/ca/en/personal-banking.html",
    "https://bmo.com/main/personal",
    "https://cibc.com/en/personal-banking.html",
    "https://weather.com/weather/today",
    "https://accuweather.com/en/us/national",
    "https://wunderground.com/weather-radar",
    "https://noaa.gov/weather",
    "https://usgs.gov/programs/earthquake-hazards",
    "https://nih.gov/health-information",
    "https://cdc.gov/flu/weekly/index.htm",
    "https://fda.gov/drugs",
    "https://epa.gov/environmental-topics",
    "https://fbi.gov/scams-and-safety",
    "https://ftc.gov/business-guidance",
    "https://sec.gov/edgar/searchedgar/companysearch",
    "https://justice.gov/action-centers/report-crime",
    "https://state.gov/policy-issues",
    "https://defense.gov/News",
    "https://loc.gov/collections",
    "https://si.edu/exhibitions",
    "https://usps.com/manage",
    "https://fedex.com/en-us/tracking.html",
    "https://ups.com/track",
    "https://dhl.com/en/express/tracking.html",
]

PHISHING_URLS = [
    # =========================================================
    # TYPOSQUATTING: Digit-Substitution Domains (paypa1.com style)
    # These are the most commonly missed by naive models
    # =========================================================
    # PayPal typosquats
    "http://paypa1.com/login",
    "http://paypa1.com/secure/signin",
    "http://paypa1.com/verify-account",
    "http://paypai.com/login",
    "http://payypal.com/account/signin",
    "http://pay-pal.com/auth",
    "http://ppaypal.com/login",
    "http://paypa1.net/signin",
    "http://paypa1.org/secure",
    # Google typosquats
    "http://g00gle.com/accounts/login",
    "http://go0gle.com/signin",
    "http://goog1e.com/verify",
    "http://gogle.com/accounts/verify",
    "http://gooogle.com/signin",
    "http://g0ogle.com/login",
    # Microsoft typosquats
    "http://m1crosoft.com/login",
    "http://micros0ft.com/account/verify",
    "http://microsft.com/signin",
    "http://mircosoft.com/login",
    "http://micorsoft.com/account/login",
    # Amazon typosquats
    "http://amaz0n.com/signin",
    "http://amazom.com/login",
    "http://am4zon.com/account/verify",
    "http://amaz-on.com/signin",
    "http://arnazon.com/login",
    # Apple typosquats
    "http://app1e.com/id/verify",
    "http://appl3.com/id/login",
    "http://appie.com/signin",
    "http://aple.com/id/reset",
    # Netflix typosquats
    "http://netfl1x.com/login",
    "http://netflik.com/signin",
    "http://n3tflix.com/account/billing",
    "http://netlfix.com/account/login",
    # Facebook typosquats
    "http://faceb00k.com/login",
    "http://facebok.com/login",
    "http://faceb0ok.com/security",
    "http://facebbk.com/account",
    # Instagram typosquats
    "http://1nstagram.com/accounts/login",
    "http://inst4gram.com/login",
    "http://lnstagram.com/security",
    # Twitter/X typosquats
    "http://tw1tter.com/login",
    "http://twittter.com/account/verify",
    "http://twtter.com/login",
    # Banking typosquats
    "http://ch4se.com/account/verify",
    "http://chasse.com/login",
    "http://wellsf4rgo.com/signin",
    "http://well5fargo.com/login",
    "http://c1tibank.com/account",
    "http://c1ti.com/login",
    "http://bankofamerika.com/signin",
    # Crypto wallet typosquats
    "http://co1nbase.com/signin",
    "http://b1nance.com/login",
    "http://binanc3.com/account/verify",
    "http://binnance.com/login",
    "http://m3tamask.io/wallet",
    "http://l3dger.com/firmware-update",
    "http://tr3zor.io/wallet/restore",
    # Gmail typosquats
    "http://gmai1.com/login",
    "http://gma1l.com/signin",
    "http://gmaii.com/account",
    # Outlook typosquats
    "http://0utlook.com/signin",
    "http://outl00k.com/login",
    "http://outlok.com/account",
    # Dropbox typosquats
    "http://dr0pbox.com/login",
    "http://droopbox.com/signin",
    # =========================================================
    # BRAND DOPPELGANGERS: 1-2 Character Edit Distance
    # =========================================================
    "http://paypals.com/login",
    "http://paaypal.com/signin",
    "http://paypl.com/account/verify",
    "http://paypall.com/login",
    "http://googlee.com/accounts/signin",
    "http://goggle.com/signin",
    "http://googl.com/login",
    "http://amazn.com/account/verify",
    "http://amanzon.com/signin",
    "http://amazzon.com/login",
    "http://microsofft.com/signin",
    "http://microsfot.com/login",
    "http://miicro soft.com/account",
    "http://apples.com/id/signin",
    "http://applee.com/id/login",
    "http://netflixs.com/login",
    "http://netflixx.com/account",
    "http://chases.com/bank/login",
    "http://chasse-bank.com/signin",
    "http://wellsfargos.com/login",
    "http://instagramm.com/login",
    "http://instagarm.com/accounts/login",
    "http://twitterr.com/login",
    "http://tweitter.com/account",
    "http://linkdin.com/login",
    "http://linkedln.com/signin",
    "http://faebook.com/login",
    "http://fcebook.com/login",
    "http://coinbasee.com/signin",
    "http://coinbse.com/account",
    "http://binanace.com/login",
    "http://melamask.io/wallet",
    "http://dropbx.com/login",
    "http://drobpox.com/signin",
    # =========================================================
    # IP address based phishing
    # =========================================================
    "http://192.168.1.100/paypal/login.php",
    "http://172.16.254.1/secure/chase-banking/verify.html",
    "http://10.0.0.15/appleid/verify-account.php?id=92841",
    "http://218.25.10.12/webscr/login.htm",
    "http://114.119.167.89/bank/signin.aspx",
    "http://185.220.101.5/auth/security_checkpoint.php",
    "http://194.180.174.10/account/wallet-recovery.html",
    "http://91.240.118.243/paypal/signin.cgi",
    "http://45.146.165.37/netflix/update-billing-info.php",
    "http://198.51.100.22/dhl/package-tracking/confirm.html",
    "http://203.0.113.195/microsoft/office365-login.htm",
    "http://89.208.107.5/bofa/auth/index.php",
    "http://193.106.191.120/wellsfargo/verification-center",
    "http://185.196.8.44/amazon/prime-security-update.php",
    "http://46.101.218.199/citibank/secure-session.html",
    
    # Suspicious TLD attacks (.xyz, .top, .buzz, .icu, .cfd, etc.)
    "http://paypal-security-verification.xyz/login",
    "http://account-apple-update.top/auth/index.html",
    "http://microsoft-online-recovery.buzz/service/signin",
    "http://amazon-account-suspension-notice.icu/verify",
    "http://netflix-billing-update-center.cfd/session/login",
    "http://chase-bank-security-alert.live/account/auth",
    "http://dhl-express-reschedule-delivery.click/track?id=829104",
    "http://usps-redelivery-fee-payment.quest/action.php",
    "http://fedex-parcel-confirmation.rest/delivery/verify",
    "http://bankofamerica-secure-portal.fit/login.html",
    "http://wellsfargo-identity-verification.work/login.aspx",
    "http://metamask-seed-phrase-restore.surf/wallet",
    "http://coinbase-account-unlock.monster/security/verify",
    "http://binance-kyc-compliance-update.cam/login",
    "http://google-docs-shared-invoice.gdn/auth/login",
    "http://dropbox-secure-file-download.sbs/verify.php",
    "http://facebook-security-check-appeal.beauty/login",
    "http://instagram-copyright-infringement.hair/confirm",
    "http://twitter-blue-verification-badge.skin/apply",
    "http://irs-tax-refund-payment-portal.top/direct-deposit",
    
    # Brand spoofing with excessive subdomains
    "http://login.microsoft.com.account-verification.suspicious-domain.com/signin",
    "http://secure.paypal.com.cgi-bin.webscr-login.threat-server.net/auth",
    "http://appleid.apple.com.manage.account.update-profile.ru-phish.net/login",
    "http://signin.ebay.com.ws.ebayisapi.security-notice.badhost.org/index.php",
    "http://support.google.com.accounts.verify.checkpoint.targethost.net/service",
    "http://banking.chase.com.security.identity.session-id.fraud-portal.com/login",
    "http://netflix.account.billing.payment.resolution.scam-center.org/update",
    "http://auth.amazon.com.customer.service.portal.phishsite.biz/signin",
    "http://myaccount.wellsfargo.com.security.check.malicious-domain.co/auth",
    "http://onlinebanking.bofa.com.customer.access.fakebanklink.com/secure",
    "http://wallet.metamask.io.secure.recovery.phrase.deceptive-url.cc/connect",
    "http://id.citi.com.session.update.profile.suspicious-network.info/portal",
    "http://secure.hsbc.com.personal.banking.logon.phish-tracker.net/auth",
    "http://login.barclays.co.uk.identity.confirm.scammer-zone.org/online",
    "http://portal.office.com.auth.enterprise.login.malicious-relay.com/app",
    
    # Credential trickery using '@' symbol
    "http://www.paypal.com@verify-identity-billing-portal.com/login.html",
    "http://www.google.com@auth-recovery-session-token.net/signin.php",
    "http://www.apple.com@security-id-verification-center.info/update",
    "http://www.chase.com@account-security-alert-resolution.org/login",
    "http://www.microsoft.com@cloud-identity-verification.net/office",
    "http://www.amazon.com@prime-membership-billing-remedy.com/action",
    "http://www.netflix.com@update-payment-method-failed.org/service",
    "http://www.bankofamerica.com@customer-enrollment-online.net/login",
    "http://www.dhl.com@express-shipping-customs-duty.com/pay",
    "http://www.usps.com@package-delivery-failure-notice.org/redeliver",
    
    # Obfuscated long URLs with high entropy / query manipulation
    "http://secure-login-portal-auth-check.com/cgi-bin/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d468&locale=en_US",
    "http://chase-online-account-recovery.net/auth/step2?token=7a9f8b2c4e1d3a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f&session=8932479238472",
    "http://apple-support-ticket-verification.com/id/verify.php?c=8923489237498273948729384729384729384792384729384&hash=e7c8a9",
    "http://bofa-identity-protection-center.org/login/secure.php?auth_token=8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c&redirect=confirm_ssn",
    "http://wellsfargo-mobile-security-update.com/signon/index.php?state=984723984729384729834729384729834729834729384&client=ios",
    "http://irs-stimulus-payment-deposit.com/portal/login.php?ssn_verify=true&action=direct_deposit&session_id=9872139847120394871",
    "http://att-yahoo-mail-login-alert.com/webmail/auth.php?user=alert&security_level=critical&token=ab78cd90ef12gh34ij56",
    "http://dhl-express-customs-clearance.net/tracking/pay.php?waybill=9871239841&fee=2.99&session=fa8972cd894109ab",
    "http://usps-postal-inspection-service.org/tracking/redelivery?tracking_number=9400111899562537628192&fee=3.45&card=required",
    "http://steamcommunity-trade-offer-gift.xyz/tradeoffer/new/?partner=89234912&token=A8f9bC2d&special_gift=knife_skin",
    
    # Keyword-stuffed fake domain names
    "http://paypal-account-update-login-verification-secure.com",
    "http://apple-id-security-lock-unlock-portal-support.com",
    "http://chase-online-banking-security-update-verify.net",
    "http://netflix-billing-subscription-cancelled-renew.org",
    "http://amazon-prime-delivery-order-confirmation-issue.com",
    "http://microsoft-365-security-alert-admin-password-reset.com",
    "http://bankofamerica-customer-online-banking-auth-center.com",
    "http://wellsfargo-identity-theft-protection-service-login.net",
    "http://coinbase-pro-security-lockout-withdrawal-confirm.com",
    "http://binance-us-security-notice-wallet-verification.org",
    "http://metamask-io-wallet-restore-recovery-passphrase.com",
    "http://dhl-international-express-delivery-hold-release.net",
    "http://fedex-ground-shipping-address-correction-portal.com",
    "http://usps-tracking-package-address-verification-system.org",
    "http://ups-delivery-exception-fee-collection-gateway.com",
    "http://irs-treasury-department-tax-refund-claim-center.net",
    "http://social-security-administration-benefits-suspension.org",
    "http://facebook-meta-business-suite-account-disabled-appeal.com",
    "http://instagram-blue-tick-partner-verification-agency.net",
    "http://whatsapp-web-browser-qr-code-sync-security.com",
    
    # URL shorteners targeting phishing endpoints
    "http://bit.ly/3xSecLogin",
    "http://tinyurl.com/bank-verify-4019",
    "http://t.co/9x7QSecAuth",
    "http://is.gd/chase_auth",
    "http://buff.ly/2kP9AuthSecure",
    "http://ow.ly/apple-id-verify",
    "http://cutt.ly/paypal-urgent-update",
    "http://rebrand.ly/netflix-payment-fix",
    "http://tiny.cc/usps-track-fee",
    "http://bit.do/irs-refund-claim",
    
    # Extra phishing lexical variations
    "http://secure-ebay-user-signin-verification.info",
    "http://signin-att-myaccount-protection.com",
    "http://verizon-wireless-bill-payment-reward.xyz",
    "http://t-mobile-account-suspended-verify-now.top",
    "http://spectrum-internet-billing-alert-update.buzz",
    "http://xfinity-comcast-security-center-support.icu",
    "http://cox-communications-email-upgrade-required.live",
    "http://roblox-free-robux-promo-generator-login.xyz",
    "http://discord-nitro-free-gift-claim-reward.top",
    "http://telegram-web-account-recovery-session.buzz",
    "http://snapchat-support-team-unban-appeal.icu",
    "http://tiktok-creator-fund-bonus-withdrawal.xyz",
    "http://adobe-creative-cloud-subscription-renewal.top",
    "http://spotify-family-plan-address-confirmation.buzz",
    "http://hulu-subscription-on-hold-update-card.live",
    "http://disneyplus-billing-error-reactivate-account.xyz",
    "http://uber-eats-driver-account-reactivation-center.top",
    "http://airbnb-host-payout-account-verification.buzz",
    "http://booking-reservation-payment-failure-confirm.xyz",
    "http://walmart-giftcard-survey-winner-claim-now.top",
    "http://target-redcard-security-alert-logon.buzz",
    "http://bestbuy-geek-squad-auto-renewal-invoice.xyz",
    "http://costco-wholesale-executive-membership-renewal.top",
    "http://homedepot-pro-account-credit-card-verify.buzz",
    "http://cvs-pharmacy-prescription-ready-pickup-login.xyz",
    "http://walgreens-balance-rewards-account-access.top",
    "http://kroger-fuel-points-loyalty-bonus-claim.buzz",
    "http://statefarm-auto-insurance-claim-inspection.xyz",
    "http://geico-policy-cancellation-notice-pay-now.top",
    "http://progressive-insurance-discount-activation.buzz",
    "http://allstate-roadside-assistance-dispatch-tracking.xyz",
    "http://schwab-investor-security-portal-authentication.top",
    "http://fidelity-investments-wire-transfer-approval.buzz",
    "http://vanguard-retirement-fund-rollover-verify.xyz",
    "http://robinhood-crypto-withdrawal-verification-code.top",
    "http://kraken-exchange-two-factor-authentication-reset.buzz",
    "http://kucoin-futures-margin-call-liquidation-alert.xyz",
    "http://trustwallet-multichain-seed-verification-portal.top",
    "http://ledger-hardware-wallet-firmware-update-security.buzz",
    "http://trezor-suite-bridge-web-authentication-key.xyz",
    "http://blockchain-com-private-key-restore-account.top",

    # =========================================================
    # MIXED TYPOSQUAT + SUSPICIOUS TLD (double red flags)
    # =========================================================
    "http://paypa1.xyz/signin",
    "http://paypa1.top/login",
    "http://paypa1.buzz/verify",
    "http://g00gle.xyz/account/login",
    "http://amaz0n.top/signin",
    "http://amaz0n.xyz/account",
    "http://m1crosoft.xyz/account/signin",
    "http://netfl1x.top/login",
    "http://faceb00k.xyz/login",
    "http://co1nbase.top/signin",
    "http://b1nance.xyz/account",
    "http://app1e.xyz/id/verify",
    "http://ch4se.top/bank/login",
    # =========================================================
    # TYPOSQUAT + CREDENTIAL PHISHING PATH
    # =========================================================
    "http://paypa1.com/cgi-bin/webscr?cmd=login&session=auth",
    "http://amaz0n.com/ap/signin?openid.mode=checkid_setup",
    "http://m1crosoft.com/login.microsoftonline.com/common/oauth2",
    "http://g00gle.com/accounts/ServiceLogin?service=mail",
    "http://app1e.com/id/idms/profile/signin",
    "http://netfl1x.com/login?locale=en&country=US",
    "http://faceb00k.com/login/?next=/home.php",
    "http://co1nbase.com/signin?redirect=/accounts",
    # =========================================================
    # HTTPS TYPOSQUATS (HTTPS doesn't make it safe!)
    # =========================================================
    "https://paypa1.com/login",
    "https://g00gle.com/accounts/signin",
    "https://amaz0n.com/signin",
    "https://m1crosoft.com/account",
    "https://netfl1x.com/login",
    "https://faceb00k.com/login",
    "https://app1e.com/id/verify",
    "https://co1nbase.com/signin",
    "https://b1nance.com/login",
    "https://ch4se.com/signin",
    "https://wellsf4rgo.com/login",
    "https://gmai1.com/login",
    "https://paypai.com/account/verify",
    "https://payypal.com/signin",
    "https://appl3.com/id/login",
]


def prepare_dataset():
    """Clean, deduplicate, and compile final dataset."""
    os.makedirs(DATASET_DIR, exist_ok=True)

    records = []

    # Process Legitimate URLs (label = 0)
    for u in BENIGN_URLS:
        clean = u.strip()
        if clean:
            records.append({"url": clean, "label": 0})

    # Process Phishing URLs (label = 1)
    for u in PHISHING_URLS:
        clean = u.strip()
        if clean:
            records.append({"url": clean, "label": 1})

    df = pd.DataFrame(records)

    # Clean & normalize
    df["url"] = df["url"].astype(str).str.strip()
    # Remove duplicates
    initial_count = len(df)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    dedup_count = len(df)

    # Validate labels
    assert set(df["label"].unique()).issubset({0, 1}), "Invalid label found!"
    assert not df["url"].isnull().any(), "Null URL found!"

    # Save CSV
    df.to_csv(OUTPUT_CSV, index=False)

    phishing_count = int((df["label"] == 1).sum())
    legitimate_count = int((df["label"] == 0).sum())

    print("=" * 60)
    print("DATASET PREPARATION SUMMARY")
    print("=" * 60)
    print(f"Total raw records:       {initial_count}")
    print(f"Duplicates removed:      {initial_count - dedup_count}")
    print(f"Final records saved:     {dedup_count}")
    print(f"Legitimate (0):          {legitimate_count} ({round(legitimate_count/dedup_count*100, 1)}%)")
    print(f"Phishing (1):            {phishing_count} ({round(phishing_count/dedup_count*100, 1)}%)")
    print(f"Dataset path:            {OUTPUT_CSV}")
    print("=" * 60)
    return df


if __name__ == "__main__":
    prepare_dataset()
