import requests
import tweepy
import praw
import logging
from datetime import datetime, timedelta
from geopy.geocoders import Nominatim
from bs4 import BeautifulSoup
import time
import json
from advanced_web_intelligence import AdvancedWebIntelligenceCollector

logger = logging.getLogger(__name__)

class OSINTCollector:
    def __init__(self, config):
        self.config = config
        self.geolocator = Nominatim(user_agent=config.REDDIT_USER_AGENT)
        
        self.twitter_api = None
        self.reddit_api = None
        self.web_intelligence = AdvancedWebIntelligenceCollector(config) if config.WEB_SEARCH_ENABLE else None
        
        self._setup_twitter_api()
        self._setup_reddit_api()
    
    def _setup_twitter_api(self):
        if not all([
            self.config.TWITTER_API_KEY,
            self.config.TWITTER_API_SECRET,
            self.config.TWITTER_ACCESS_TOKEN,
            self.config.TWITTER_ACCESS_TOKEN_SECRET
        ]):
            logger.warning("Twitter API credentials not configured")
            return
            
        try:
            auth = tweepy.OAuthHandler(
                self.config.TWITTER_API_KEY, 
                self.config.TWITTER_API_SECRET
            )
            auth.set_access_token(
                self.config.TWITTER_ACCESS_TOKEN,
                self.config.TWITTER_ACCESS_TOKEN_SECRET
            )
            self.twitter_api = tweepy.API(auth, wait_on_rate_limit=True)
            
            self.twitter_api.verify_credentials()
            logger.info("Twitter API authentication successful")
            
        except Exception as e:
            logger.error(f"Twitter API setup failed: {e}")
    
    def _setup_reddit_api(self):
        if not all([
            self.config.REDDIT_CLIENT_ID,
            self.config.REDDIT_CLIENT_SECRET
        ]):
            logger.warning("Reddit API credentials not configured")
            return
            
        try:
            self.reddit_api = praw.Reddit(
                client_id=self.config.REDDIT_CLIENT_ID,
                client_secret=self.config.REDDIT_CLIENT_SECRET,
                user_agent=self.config.REDDIT_USER_AGENT
            )
            logger.info("Reddit API setup successful")
            
        except Exception as e:
            logger.error(f"Reddit API setup failed: {e}")
    
    def collect_twitter_data(self, location, start_time, end_time, keywords=None):
        if not self.twitter_api:
            logger.error("Twitter API not available")
            return []
            
        try:
            geocode = self._get_geocode(location)
            if not geocode:
                logger.error(f"Could not geocode location: {location}")
                return []
                
            query_parts = []
            if keywords:
                if isinstance(keywords, list):
                    query_parts.extend(keywords)
                else:
                    query_parts.append(keywords)
            
            query = " OR ".join(query_parts) if query_parts else "*"
            
            tweets = []
            for tweet in tweepy.Cursor(
                self.twitter_api.search_tweets,
                q=query,
                geocode=f"{geocode['lat']},{geocode['lon']},{self.config.MAX_CORRELATION_DISTANCE_KM}km",
                since=start_time.strftime('%Y-%m-%d'),
                until=(end_time + timedelta(days=1)).strftime('%Y-%m-%d'),
                tweet_mode='extended',
                result_type='mixed'
            ).items(self.config.MAX_OSINT_RESULTS):
                
                if start_time <= tweet.created_at <= end_time:
                    tweets.append({
                        'timestamp': tweet.created_at,
                        'source': 'twitter',
                        'content': tweet.full_text,
                        'author': tweet.author.screen_name,
                        'location': getattr(tweet, 'place', {}).get('full_name', '') if hasattr(tweet, 'place') and tweet.place else '',
                        'coordinates': self._extract_coordinates(tweet),
                        'engagement': {
                            'retweets': tweet.retweet_count,
                            'favorites': tweet.favorite_count,
                            'replies': tweet.reply_count if hasattr(tweet, 'reply_count') else 0
                        },
                        'url': f"https://twitter.com/{tweet.author.screen_name}/status/{tweet.id}",
                        'data': {
                            'hashtags': [hashtag['text'] for hashtag in tweet.entities.get('hashtags', [])],
                            'mentions': [mention['screen_name'] for mention in tweet.entities.get('user_mentions', [])],
                            'urls': [url['expanded_url'] for url in tweet.entities.get('urls', [])]
                        }
                    })
                    
            return tweets
            
        except Exception as e:
            logger.error(f"Error collecting Twitter data: {e}")
            return []
    
    def collect_reddit_data(self, location, start_time, end_time, subreddits=None, keywords=None):
        if not self.reddit_api:
            logger.error("Reddit API not available")
            return []
            
        try:
            posts = []
            search_terms = keywords if keywords else [""]
            target_subreddits = subreddits if subreddits else ["all"]
            
            for subreddit_name in target_subreddits:
                try:
                    subreddit = self.reddit_api.subreddit(subreddit_name)
                    
                    for search_term in search_terms:
                        for submission in subreddit.search(
                            search_term, 
                            time_filter="all",
                            sort="new",
                            limit=self.config.MAX_OSINT_RESULTS // len(target_subreddits) // len(search_terms)
                        ):
                            post_time = datetime.fromtimestamp(submission.created_utc)
                            
                            if start_time <= post_time <= end_time:
                                posts.append({
                                    'timestamp': post_time,
                                    'source': 'reddit',
                                    'content': f"{submission.title}\n{submission.selftext}"[:1000],
                                    'author': str(submission.author) if submission.author else '[deleted]',
                                    'location': location,
                                    'coordinates': None,
                                    'engagement': {
                                        'score': submission.score,
                                        'upvote_ratio': submission.upvote_ratio,
                                        'comments': submission.num_comments
                                    },
                                    'url': f"https://reddit.com{submission.permalink}",
                                    'data': {
                                        'subreddit': submission.subreddit.display_name,
                                        'flair': submission.link_flair_text,
                                        'gilded': submission.gilded,
                                        'stickied': submission.stickied
                                    }
                                })
                                
                except Exception as e:
                    logger.warning(f"Error processing subreddit {subreddit_name}: {e}")
                    continue
                    
            return posts
            
        except Exception as e:
            logger.error(f"Error collecting Reddit data: {e}")
            return []
    
    def collect_news_data(self, location, start_time, end_time, keywords=None):
        try:
            articles = []
            
            if self.config.NEWS_API_KEY:
                articles.extend(self._collect_newsapi_data(location, start_time, end_time, keywords))
            
            articles.extend(self._collect_google_news_data(location, start_time, end_time, keywords))
            
            return articles
            
        except Exception as e:
            logger.error(f"Error collecting news data: {e}")
            return []
    
    def _collect_newsapi_data(self, location, start_time, end_time, keywords):
        try:
            url = "https://newsapi.org/v2/everything"
            
            query_parts = [location]
            if keywords:
                if isinstance(keywords, list):
                    query_parts.extend(keywords)
                else:
                    query_parts.append(keywords)
            
            params = {
                'q': " AND ".join(query_parts),
                'from': start_time.strftime('%Y-%m-%d'),
                'to': end_time.strftime('%Y-%m-%d'),
                'sortBy': 'publishedAt',
                'language': 'en',
                'pageSize': min(100, self.config.MAX_OSINT_RESULTS),
                'apiKey': self.config.NEWS_API_KEY
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            articles = []
            
            for article in data.get('articles', []):
                pub_date = datetime.fromisoformat(article['publishedAt'].replace('Z', '+00:00'))
                
                articles.append({
                    'timestamp': pub_date,
                    'source': 'news_api',
                    'content': f"{article['title']}\n{article.get('description', '')}"[:1000],
                    'author': article.get('author', 'Unknown'),
                    'location': location,
                    'coordinates': None,
                    'engagement': {},
                    'url': article['url'],
                    'data': {
                        'source_name': article['source']['name'],
                        'image_url': article.get('urlToImage', ''),
                        'content_preview': article.get('content', '')[:200]
                    }
                })
                
            return articles
            
        except Exception as e:
            logger.error(f"Error with NewsAPI: {e}")
            return []
    
    def _collect_google_news_data(self, location, start_time, end_time, keywords):
        try:
            articles = []
            
            query_parts = [location]
            if keywords:
                if isinstance(keywords, list):
                    query_parts.extend(keywords)
                else:
                    query_parts.append(keywords)
            
            query = " ".join(query_parts)
            
            search_url = f"https://news.google.com/rss/search?q={requests.utils.quote(query)}&hl=en-US&gl=US&ceid=US:en"
            
            response = requests.get(search_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'xml')
            
            for item in soup.find_all('item')[:min(50, self.config.MAX_OSINT_RESULTS)]:
                try:
                    pub_date_str = item.pubDate.text
                    pub_date = datetime.strptime(pub_date_str, '%a, %d %b %Y %H:%M:%S %Z')
                    
                    if start_time <= pub_date <= end_time:
                        articles.append({
                            'timestamp': pub_date,
                            'source': 'google_news',
                            'content': f"{item.title.text}\n{item.description.text if item.description else ''}"[:1000],
                            'author': 'Unknown',
                            'location': location,
                            'coordinates': None,
                            'engagement': {},
                            'url': item.link.text,
                            'data': {
                                'source_name': 'Google News',
                                'guid': item.guid.text if item.guid else ''
                            }
                        })
                        
                except Exception as e:
                    logger.debug(f"Error processing news item: {e}")
                    continue
                    
            return articles
            
        except Exception as e:
            logger.error(f"Error with Google News: {e}")
            return []
    
    def _get_geocode(self, location):
        try:
            location_data = self.geolocator.geocode(location)
            if location_data:
                return {
                    'lat': location_data.latitude,
                    'lon': location_data.longitude,
                    'address': location_data.address
                }
        except Exception as e:
            logger.error(f"Geocoding error: {e}")
        return None
    
    def _extract_coordinates(self, tweet):
        if hasattr(tweet, 'coordinates') and tweet.coordinates:
            return {
                'lat': tweet.coordinates['coordinates'][1],
                'lon': tweet.coordinates['coordinates'][0]
            }
        elif hasattr(tweet, 'place') and tweet.place and tweet.place.bounding_box:
            coords = tweet.place.bounding_box.coordinates[0]
            center_lon = sum(coord[0] for coord in coords) / len(coords)
            center_lat = sum(coord[1] for coord in coords) / len(coords)
            return {'lat': center_lat, 'lon': center_lon}
        return None
    
    def collect_web_intelligence(self, forensic_context, location, start_time, end_time, keywords=None, context_notes=""):
        # this is where the magic happens - LLM helps us find relevant stuff
        
        if not self.web_intelligence:
            logger.warning("Web intelligence collection is disabled")
            return []
        
        try:
            # prep the forensic data for the LLM to understand
            context = {
                'location': location,
                'timeframe': f"{start_time} to {end_time}",
                'keywords': keywords or [],
                'context_notes': context_notes
            }
            
            if isinstance(forensic_context, list) and forensic_context:
                # pull out the interesting bits from forensic data
                file_types = list(set(event.get('file_type', 'unknown') for event in forensic_context))
                event_types = list(set(event.get('event_type', 'unknown') for event in forensic_context))
                suspicious_files = [
                    event.get('file_path', '') for event in forensic_context
                    if any(ext in event.get('file_path', '').lower() 
                          for ext in ['.exe', '.bat', '.ps1', '.dll', '.scr', '.com'])
                ]
                
                context.update({
                    'file_types': file_types,
                    'event_types': event_types,
                    'suspicious_files': suspicious_files[:10]  # don't want to overwhelm the LLM
                })
            
            logger.info("Starting advanced LLM-powered web intelligence collection with context notes")
            web_data = self.web_intelligence.collect_comprehensive_intelligence(
                forensic_context=context,
                location=location,
                start_time=start_time,
                end_time=end_time
            )
            
            return web_data
            
        except Exception as e:
            logger.error(f"Error collecting web intelligence: {e}")
            return []
    
    def collect_all_sources(self, location, start_time, end_time, keywords=None, subreddits=None, forensic_context=None):
        all_data = []
        
        logger.info(f"Collecting OSINT data for {location} from {start_time} to {end_time}")
        
        # good old fashioned API scraping
        twitter_data = self.collect_twitter_data(location, start_time, end_time, keywords)
        all_data.extend(twitter_data)
        logger.info(f"Collected {len(twitter_data)} Twitter posts")
        
        reddit_data = self.collect_reddit_data(location, start_time, end_time, subreddits, keywords)
        all_data.extend(reddit_data)
        logger.info(f"Collected {len(reddit_data)} Reddit posts")
        
        news_data = self.collect_news_data(location, start_time, end_time, keywords)
        all_data.extend(news_data)
        logger.info(f"Collected {len(news_data)} news articles")
        
        # now for the smart stuff - let the LLM help us search
        if self.config.WEB_SEARCH_ENABLE and forensic_context:
            web_intelligence_data = self.collect_web_intelligence(
                forensic_context, location, start_time, end_time, keywords
            )
            all_data.extend(web_intelligence_data)
            logger.info(f"Collected {len(web_intelligence_data)} web intelligence items")
        
        all_data.sort(key=lambda x: x['timestamp'])
        logger.info(f"Total OSINT data collected: {len(all_data)} items")
        
        return all_data