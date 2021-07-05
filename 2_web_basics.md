# Web Basics
This section will cover some of the fundamental concepts around how web applications work. The more academic content is easier to capture with [Slides](https://docs.google.com/presentation/d/1yY6XPY3Ngzq2Hd14oFZe2BN-kHF2KhkQwGWxtMJwZnE), so please go and read through those now.

Great! Now that you have a rough sense for how HTTP works, it's time to practice the concepts with hands-on examples.

## Enable Capturing Responses
1. Click **Proxy**
2. Click **Options**
3. Under **Intercept Server Responses**, check the box next to **Intercept responses based on the following rules:**

## Observing what happens when we go to a site
1. Click the **Intercept** tab
2. Click **Intercept is off** to turn intercept mode back on
3. In the burp browser, go to [https://google.com/](https://google.com/)
4. Take a moment to review the contents of your first intercepted request. Be sure to revisit the slides as needed to acclimate yourself with the various headers. 
5. Click **Forward** to see the associated response.
6. Keep clicking **Forward** to see the various requests and responses that make up your browser communicating with google.com - it's probably a lot more complicated than you thought.

## HTTP History
It's a bit unwieldy to keep having to click **Forward**, and there isn't an easy way to review previous web traffic. This is where Burp's HTTP history tab is incredibly useful.

1. Click **Intercept is on** to turn intercept off
2. Click **HTTP history** to view all of the requests and responses you've accumulated
3. Click the `#` in the upper left-hand side to modify the order (ascending or descending) of the listed requests

Feel free to spend time later trying this out with several of the sites you regularly visit to get a sense of how they work.

At this point, you can move on to [Vulnerable Targets](3_vulnerable_targets.md).

## Additional Resources

[![Basics with Hammond](https://img.youtube.com/vi/G3hpAeoZ4ek/0.jpg)](https://youtu.be/G3hpAeoZ4ek)

[![TomNomNom Fundamentals](https://img.youtube.com/vi/9uebakqWlB0/0.jpg)](https://youtu.be/9uebakqWlB0)

[![Rest API](https://img.youtube.com/vi/lsMQRaeKNDk/0.jpg)](https://youtu.be/lsMQRaeKNDk)
