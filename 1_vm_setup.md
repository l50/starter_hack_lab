# Virtual Machine Setup
This section will help you to configure your kali VM that you can use to reproduce the topics covered during the presentation.

1. Fullscreen your VM
   * On Mac OS, you can use Command-F
   * On Linux, you can use Right Ctrl-F

2. Change the default password

   As you're probably aware, `vagrant/vagrant` is not the most secure password combination out there. Let's fix that real quick. Open a terminal by clicking this icon in the upper left-hand corner of the screen:

   ![](images/terminal_location.png)

   Next, run this command:
   ```
   sudo passwd vagrant
   ```

   When prompted, enter whatever password you desire. The next time you log in, this will be the password that you use for the vagrant user.

3. Install Docker

   Docker facilitates running containers. Containers are used to package applications, which makes it easier to move them to other systems and have them behave the same way as they did on your system.

   While at first glance it may seem like a similar concept to a VM, there are a few key differences. VMs use a hypervisor to virtualize physical hardware, and each VM has a guest OS along with a virtual copy of the hardware needed by the OS to run. Containers, on the other hand, virtualize the OS, so each container only needs to provide an application and its libraries.

   There's plenty more information on the internet that I encourage you to read. Containers are a big deal in the industry and won't be going anywhere anytime soon.

   Run these commands to install Docker:
   ```
   wget https://raw.githubusercontent.com/l50/starter_hack_lab/main/scripts/kali_docker.sh
   bash kali_docker.sh
   ```

   Finish up the install by rebooting your VM:
   ```
   sudo reboot
   ```

4. Start Burp

   Burp Suite is a proxy that you can use to intercept web traffic. It is immensely helpful when it comes to web application security, and I'm of the opinion that most (if not all) security professionals should have some familiarity. To run it, type this command into a terminal window:
   ```
   burpsuite
   ```

   Check the box next to **Don't show again for this JRE** and click **OK** when you see this message:

   ![](images/burp_warning.png)

   Click **I Agree** for the terms and conditions.

   If there's an update available, go ahead and click **Close**. At this point, you should be at this window:

   ![](images/burp_start.png)

   Go ahead and click **Next** and then **Start Burp**

   Burp should now be running. It'll probably look like this:

   ![](images/burp_start.png)

   Burp should be running. Go ahead and click on **Proxy** and then click **Intercept is on** to turn intercept mode off for now.

   Next, click **Open Browser**. Generally speaking, this is the window configuration I like to have when I'm working with Burp:

   ![](images/burp_window_layout.png)

   Please feel free to click **Cancel** if you see a pop up like this one:

   ![](images/annoying_popup.png)

At this point, you should feel free to move on to [Web Basics](2_web_basics.md).

## Additional Resources

* Install docker manually - [official install docs](https://docs.docker.com/engine/install/)
* What is Burp - [official documentation](https://portswigger.net/burp)
* Open Source alternative to Burp - [OWASP Zap](https://owasp.org/www-project-zap/)
<br/><br/>
[![Hammond](https://img.youtube.com/vi/T47SIBZSVOo/0.jpg)](https://youtu.be/T47SIBZSVOo)
<br/><br/>
[![Chuck](https://img.youtube.com/vi/eGz9DS-aIeY/0.jpg)](https://youtu.be/eGz9DS-aIeY)
<br/><br/>
[![Stok IDOR](https://img.youtube.com/vi/3K1-a7dnA60/0.jpg)](https://youtu.be/3K1-a7dnA60)
