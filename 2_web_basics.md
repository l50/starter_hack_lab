# Web Basics
This section will help you to understand some of the fundamental concepts around how web applications work. The content is easier to capture and discuss with [Slides](https://docs.google.com/presentation/d/1yY6XPY3Ngzq2Hd14oFZe2BN-kHF2KhkQwGWxtMJwZnE), so that's what I've opted to use.

Now that we have a sense of how HTTP works, let's see some of the things we discussed in practice.

## Enable Capturing Responses
1. Click **Proxy**
2. Click **Options**
3. Under **Intercept Server Responses**, check the box next to **Intercept responses based on the following rules:**

## Observing what happens when we go to a site
1. Click the **Intercept** tab
2. Click **Intercept is off** to turn intercept mode back on
3. In the burp browser, go to [https://google.com/](https://google.com/)
4. Observe that the first intercepted item is a request. Remember what we just talked about in terms of the various components that make up a request.
5. Click **Forward** to see the associated response.
6. Keep clicking **Forward** to see the various requests and responses that make up your browser communicating with google.com - it's probably a lot more complicated than you thought.

## HTTP History
It's a bit unwieldy to keep having to click **Forward**. I'm going to show you an area of Burp that can be helpful when you want to get a sense of how the communication is happening between your browser and a web server.

1. Click **Intercept is on** to turn it off
2. Click **HTTP history** - this has a listing of all of the requests and responses you've accumulated
3. Click the `#` in the upper left-hand side to modify the order of the requests - I like descending order myself.

Feel free to spend time later trying this out with several of the sites you regularly visit to get a sense of how they work.

At this point, you can move on to [Vulnerable Targets](3_vulnerable_targets.md).

## Additional Resources

[![Basics with Hammond](https://img.youtube.com/vi/G3hpAeoZ4ek/0.jpg)](https://youtu.be/G3hpAeoZ4ek)

[![TomNomNom Fundamentals](https://img.youtube.com/vi/9uebakqWlB0/0.jpg)](https://youtu.be/9uebakqWlB0)

[![Rest API](https://img.youtube.com/vi/lsMQRaeKNDk/0.jpg)](https://youtu.be/lsMQRaeKNDk)
