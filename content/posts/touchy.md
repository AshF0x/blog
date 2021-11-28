---
title: "Touchy Logger"
description: "The story of a weird logfile, mysterious input devices & a hacky parser"
date: 2021-11-28
---
A few weeks back, me and a friend of mine called Viktor solved a CTF challenge together that fascinated both of us.
It was fun, we learned a bunch from it and most importantly: From a pure forensics standpoint, the challenge was applicable to real life. So as a student enrolled in a Bachelor for IT Forensics & Cybercrime, that was really fun & motivating to see. So what challenge am I even talking about?

Touchy Logger was a part of the 2021 edition of the Hack.lu CTF, organized by [fluxfingers](https://fluxfingers.net/).
![test](/images/challenge.png)

The challenge was categorised under *misc*. 
After downloading the zip file and extracting it, you get presented with a file called `touch.log`.
Our first thought was: "Well this is challenge rated as low difficulty. The flag may just be obfuscated somewhere in this logfile. This won't be to hard."  

Boy were we wrong ...

## Part One: Figuring out the Logfile
After checking the linecount for the file we saw the first 'problem':
```sh
$ wc -l touch.log
9257 touch.log
```
9257 lines is quite a lot and we still had no clue what we were looking for. Just to make sure there was nothing hidden in plain sight (or text) in the logfile, we cleaned up the lines a bit and grep'ed for strings. But after a few minutes it was clear to us that the file was just containing the logs.
Now that we had that information we moved to the next step: Figuring out what kind of logfile we are dealing with.

---

To provide some context; here are head and tail of the file:  
**Head**
```
$ head -n 20 touch.log | bat 
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ STDIN
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ -event2   DEVICE_ADDED     Power Button                      seat0 default group1  cap:k
   2   │ -event19  DEVICE_ADDED     Video Bus                         seat0 default group2  cap:k
   3   │ -event1   DEVICE_ADDED     Lid Switch                        seat0 default group3  cap:S
   4   │ -event0   DEVICE_ADDED     Sleep Button                      seat0 default group4  cap:k
   5   │ -event17  DEVICE_ADDED     Integrated RGB Camera: Integrat   seat0 default group5  cap:k
   6   │ -event18  DEVICE_ADDED     Integrated RGB Camera: Integrat   seat0 default group5  cap:k
   7   │ -event5   DEVICE_ADDED     Wacom HID 525C Finger             seat0 default group6  cap:t  size 259x173mm ntouches 10 calib
   8   │ -event4   DEVICE_ADDED     Wacom HID 525C Pen                seat0 default group6  cap:T  size 259x173mm calib
   9   │ -event15  DEVICE_ADDED     Intel HID events                  seat0 default group7  cap:k
  10   │ -event3   DEVICE_ADDED     AT Translated Set 2 keyboard      seat0 default group8  cap:k
  11   │ -event16  DEVICE_ADDED     ThinkPad Extra Buttons            seat0 default group9  cap:kS
  12   │  event16  SWITCH_TOGGLE    +0.000s  switch tablet-mode state 1
  13   │ -event5   TOUCH_DOWN       +0.000s  0 (0)  1.10/97.95 ( 2.85/169.28mm)
  14   │  event5   TOUCH_FRAME      +0.000s  
  15   │  event5   TOUCH_UP         +0.044s  0 (0)
  16   │  event5   TOUCH_FRAME      +0.044s  
  17   │  event5   TOUCH_DOWN       +1.260s  0 (0) 50.12/99.97 (129.93/172.78mm)
  18   │  event5   TOUCH_FRAME      +1.260s  
  19   │  event5   TOUCH_MOTION     +1.268s  0 (0) 50.20/99.57 (130.12/172.07mm)
  20   │  event5   TOUCH_FRAME      +1.268s  
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

**Tail**
```
$ tail -n 20 touch.log | bat 
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ STDIN
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │  event5   TOUCH_UP         +664.441s    0 (0)
   2   │  event5   TOUCH_FRAME      +664.441s    
   3   │  event5   TOUCH_DOWN       +665.748s    0 (0) 22.69/96.37 (58.83/166.55mm)
   4   │  event5   TOUCH_FRAME      +665.748s    
   5   │  event5   TOUCH_UP         +665.801s    0 (0)
   6   │  event5   TOUCH_FRAME      +665.801s    
   7   │  event5   TOUCH_DOWN       +666.588s    0 (0) 30.11/80.91 (78.05/139.82mm)
   8   │  event5   TOUCH_FRAME      +666.588s    
   9   │  event5   TOUCH_MOTION     +666.653s    0 (0) 30.01/80.91 (77.80/139.82mm)
  10   │  event5   TOUCH_FRAME      +666.653s    
  11   │  event5   TOUCH_UP         +666.668s    0 (0)
  12   │  event5   TOUCH_FRAME      +666.668s    
  13   │  event5   TOUCH_DOWN       +668.204s    0 (0) 27.39/57.07 (71.00/98.62mm)
  14   │  event5   TOUCH_FRAME      +668.204s    
  15   │  event5   TOUCH_UP         +668.276s    0 (0)
  16   │  event5   TOUCH_FRAME      +668.276s    
  17   │  event5   TOUCH_DOWN       +680.856s    0 (0) 64.40/36.24 (166.95/62.62mm)
  18   │  event5   TOUCH_FRAME      +680.856s    
  19   │  event5   TOUCH_UP         +680.963s    0 (0)
  20   │  event5   TOUCH_FRAME      +680.963s    
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

The first 11 lines gave us already a lot of new information as the words **Wacom HID** and **ThinkPad Extra Buttons** hinted towards input devices. Every other line starting from the 12th had the same structure. 

![Line Structure](/images/line_struct.png)

1. It was always an event5 
2. followed by either:
	- TOUCH_UP
	- TOUCH_DOWN
	- TOUCH_FRAME
	- TOUCH_MOTION
3. The next part is the timestamp, represented in seconds since the start.
4. Some but not all lines, as you can see above, have some sort of coordinates at the end too.
	Those coordinates were represented by two values, obviously for the x and y axis on a 2 dimensional canvas.

All this new found information helped us form a much better idea of what we were dealing with. This was a logfile of an HID of some form that we needed to transform into useful information.  
Because we found a reference to Wacom and a touch pen in the first lines, we went ahead and googled for different logging and debugging solutions for Wacom Products, in the hope that we could just parse this logfile and get a representation on a canvas. This is were we spend a bunch of time, but also learned so much of what exists out there for these kind of devices. We even tried out a Wacom Tablet ourselves that I had lying around, to se if we could replicate this logfile somehow. But no luck on this end.

One interesting part that I want to mention briefly is the use of `libinput`. We learned about this library during our research. 
> It (libinput) functions as an input stack for processes that need to provide events from commonly used input devices - [Source](https://wayland.freedesktop.org/libinput/doc/latest/what-is-libinput.html)

![](https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Libinput_for_Wayland_compositors.svg/1024px-Libinput_for_Wayland_compositors.svg.png)
Source: Wikimedia

I tinkered a bit around with it to see if we could parse our eventlog to it but no chance. 
The only thing I manage to do with it propperly was to record a log myself for an input device like my mouse:
```
 248   │   udev:
 249   │     properties:
 250   │     - ID_INPUT=1
 251   │     - ID_INPUT_KEY=1
 252   │     - ID_INPUT_KEYBOARD=1
 253   │     - ID_INPUT_MOUSE=1
 254   │     - LIBINPUT_DEVICE_GROUP=3/46d/4079:usb-0000:00:14.0-4
 255   │     - MOUSE_DPI=400@1000 *800@1000 1600@1000 3200@1000 6400@1000
 256   │   quirks:
 257   │   events:
 258   │   # Current time is 17:03:22
 259   │   - evdev:
 260   │     - [  0,      0,   2,   1,      -1] # EV_REL / REL_Y                    -1
 261   │     - [  0,      0,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +0ms
 262   │   - evdev:
 263   │     - [  0,   2006,   2,   0,      -1] # EV_REL / REL_X                    -1
 264   │     - [  0,   2006,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +2ms
 265   │   - evdev:
 266   │     - [  0,   5006,   2,   0,      -1] # EV_REL / REL_X                    -1
 267   │     - [  0,   5006,   2,   1,      -1] # EV_REL / REL_Y                    -1
 268   │     - [  0,   5006,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +3ms
 269   │   - evdev:
 270   │     - [  0,   7023,   2,   0,      -1] # EV_REL / REL_X                    -1
 271   │     - [  0,   7023,   2,   1,      -1] # EV_REL / REL_Y                    -1
 272   │     - [  0,   7023,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +2ms
 273   │   - evdev:
 274   │     - [  0,   9023,   2,   0,      -1] # EV_REL / REL_X                    -1
 275   │     - [  0,   9023,   0,   0,       0] # ------------ SYN_REPORT (0) ---------- +2ms
 276   │   - evdev:
 277   │     - [  0,   9993,   2,   0,      -1] # EV_REL / REL_X                    -1
 278   │     - [  0,   9993,   2,   1,      -1] # EV_REL / REL_Y                    -1
```
The log structure was clearly different from the one we were working with. In addtition to that this got saved as a yaml file.

So after all this research, Viktor and I came to a conclusions:  
There is no (Wacom) log parser for this kind of things that could help us. Or at least we were not able to find one.
So we said F*** it, we do it ourselves and wrote a parser for the logfile to help us visualize the events

## Part Two: Visualisation
We started this part out by deciding on a language to code the parser in. 
I wanted to do it in Python or Go, Viktor on the other hand relied on his JavaScript skills.
By the time I found a solution to draw on a canvas in Python, Viktor already had a working prototype. So we stuck with JS.  

For our code we created a 2000 x 5000 canvas.
The code then went trough the logfile line by line and drew all the events on the corresponding coordinates, based on wether **TOUCH_DOWN**, **TOUCH_UP** or **TOUCH_MOTION** was used.

```js
async function draw(line, previousElement = undefined) {
	return new Promise(function(resolve, reject) {
		switch (line.Column2) {
			case "TOUCH_DOWN":
				if (drawletter) ctx.beginPath();
				var sll = line.Column3.split("/");
				var x = parseFloat(sll[0].slice(sll[0].length - 5, sll[0].length)) * 10;
				var y = parseFloat(sll[1].slice(0, 5)) * 10;
				if (drawletter) ctx.moveTo(x, y);
				checkifinbox(x, y);
				//ctx.fillRect(x * 10, y * 10, 1, 1);
				break;
			case "TOUCH_MOTION":
				var sll = line.Column3.split("/");
				var x = parseFloat(sll[0].slice(sll[0].length - 5, sll[0].length)) * 10;
				var y = parseFloat(sll[1].slice(0, 5)) * 10;
				if (drawletter) ctx.lineTo(x, y);
				// checkifinbox(x, y);
				// ctx.fillRect(x * 10, y * 10, 1, 1);
				break;

			case "TOUCH_UP":
				if (previousElement && previousElement.Column2 == "TOUCH_DOWN") {
					var sll = previousElement.Column3.split("/");
					var x = parseFloat(sll[0].slice(sll[0].length - 5, sll[0].length)) * 10;
					var y = parseFloat(sll[1].slice(0, 5)) * 10;
					if (drawletter) ctx.fillRect(x, y, 1, 1);
				}
				if (drawletter) ctx.stroke();
				break;
		}
		var parsss = parseFloat(line.Column3.split("s")[0].replace("+", ""));
		var wait = parsss - window.timer;
		window.timer = parsss;
		// console.log(parsss);
		//setTimeout(resolve, wait * 100);
		resolve();

	})
}
```
In addition to the drawing capabilities Viktor also implemented the functionality that whenever the user clicks with his mouse on the canvas, the coordinates are printed out to console.
This would come in really handy in the next part.
But before we moved on we wanted to understand what we were looking at.

Below you can see the rendered picture in the Browser:

![Rendered](/images/rendered1.png)

We were quite confused at the beginning because we expected the flag already at this step, so we were not sure if we were on the right track or if the code did not work propperly.
But some parts of the rendered image were bizzare to me.  
First of all the triangular shapes in the middle of the picture looked clearly artificially created and were not drawn by hand. The other lines at the top, on the other hand, looked like drawn with a pen or a finger on a touchpad.  
The other part that confused us even more, were the dots at the lower part of the picture.
First we thought it might have been some weird way of obfuscating text with an substitution cypher were every area would represent a specific character.
And then we finally saw it... It was a touch keyboard! Someone was typing on a device and now we wanted to know what it was and how we could reverse the picture/information into useful text.

---

Viktor went back to his code and modified it so that we could draw boxes around the areas where we saw the highest concentration of dots. 
To keep the box layout clean and realistic Viktor came up with the following solution:

```js
function makeboxes(startx, starty, alphabet) {
	for (let index = 0; index < 11; index++) {
		var addedx = index * 52.5;
		var addedy = index * 60;
		var box = {
			topleftx: startx + addedx,
			toplefty: starty,
			toprightx: startx + addedx,
			toprighty: starty,
			botleftx: startx + addedx,
			botlefty: starty,
			botrightx: startx + addedx,
			botrighty: starty,
		}
		if (alphabet) box.alph = alphabet.shift()
		window.ctx.beginPath();
		//  console.log(box);
		window.ctx.strokeStyle = "red";
		window.ctx.rect(box.topleftx, box.toplefty, 52.5, 60);
		window.ctx.stroke();
		kb.push(box);
	}
	console.log(kb)
}

var c = document.getElementById("myCanvas");
window.ctx = c.getContext("2d");

makeboxes(200, 700, ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p", " backspace "])

makeboxes(228, 780, ["a", "s", "d", "f", "g", "h", "j", "k", "l", " ENTER ", " ENTER "])

makeboxes(210, 860, [" SHIFT ", "z", "x", "c", "v", "b", "n", "m", " SHIFT ", " SHIFT ", " SHIFT "])

makeboxes(210, 940, [" CTRL ", ",", " ", " ", " ", " ", " ", ".", " ", " ", " ", " ", " "])
async function parseData() {

	for (let index = 0; index < data.length; index++) {
		const element = data[index];
		if (index > 0) var previousElement = data[index - 1]
		draw(element, previousElement);

	}
```

The idea here was simple:
- Define the boxes and their areas (and draw them once on the canvas for the user to see)
- Every box gets a string assigned that helps us identify it, like for example the character 'q'
- At every event that happens inside of one of those boxes, the assigned identifier gets appended to a long string
- As soon as there is an event outside of one of the boxes, the string ends, gets pushed on an array and also gets printed out to the console

Below is the newly rendered logfile in the browser, this time with the boxes drawn. On the righthand side the console shows the output we just talked about.

![Rendered 2](/images/rendered2.png)

The way our code handled the touch events also enabled us to filter out the noise that was artificially created. So we only saw the events that were relevant for us. This was possible due to figuring out timings between the different events like **TOUCH_DOWN** and **TOUCH_UP** and how far the coordinates moved when the "pen" was touching down.

![Boxes](/images/boxes.png)

Here another zoomed in view of the console log in the Browser.

![Extracted Text](/images/extracted_text.png)

As it is shown in the console, the code was working although it was not perfect. We still had two issues here:
1. We were not sure how to deal with the modifiers like ctrl, shift etc.
	For now they are just getting printed to console and we interpreted the changes ourselves (like capitalisation of characters etc.)
2. We were also not sure what keyboard layout we should use for our mapping. 
	The one we used was the first that came to our mind that looked similar, which was the iOS 13 keyboard.
	Again: Not knowing what layout we were dealing with made it also hard to know the right modifiers.

We found a momentarly solutions to both of these problems by just ignoring them.
Although we had no idea how to find the right keyboard layout in the long run, we knew we were not far off. 
The console output gave us already a good idea what we were looking at so we could replicate the users behavior step by step:
- Opening Firefox
- visiting reddit.com/r/stocks
- visiting Twitter and searching for "stocks to buy"
- entering the string "stocks.live"
- Next the user send a message to another user called "wolfgang". Here we also found our users name at the end of the message: "manfred".

The message contained a whole lot of modifiers so we took a somewhat "bruteforcie" aproach to the figure out the right special & missing characters.   
As we kind of knew what the correct message would look like we tried reverse different combinations and saw if they also fitted in other places in the text. 
When they made sense Viktor adapted the assignment of the character in the code and we ran the code again. With this method we came very close to the right keyboard layout without figuring out so far which one we were dealing with.

Then at the end of the console output it gets interesting for us. Manfred visits https://investment24.flu.xxx where he proceeds to login with his credentials.

![Login Portal](/images/login_portal.png)

This was the last problem for us to solve though: The username **fluxmanfred** was clear to read and made sense, but the password did not work. So we clearly had another issue in our assigned keyboard layout.

![Credentials](/images/creds.png)

In a last desperate attempt I tried to slowly bruteforce the password with different modifications as we were only unsure about a handfull of characters, but after a short while gave up on this.
At this point we knew that we had to find the right keyboard to solve this. 
We looked into old iOS keyboard layouts, tried them out in emulators,  tried the Windows one as we thought the logfile was maybe created on a ThinkPad and also tried a bunch of Android ones.
So I did what every sane person would do: I headed to bed.

Naturally Viktor found the right one 5 minutes later: The Ubuntu OnScreen Keyboard... Obviously.
![Keyboard Layout](/images/ubuntu_keyboard.png)
He immediately filled out the missing characters that we were unsure about and ran the parser one more time. This time he got the right password and could login and got rewarded with the flag.

## Part Three: Closing Thoughts
In hinsight the hardest part of this challenge was finding the right keyboard layout. When you compare the Ubuntu layout with the picture of boxes we've drawn, there are clear differences in the size and positions of the buttons.

Like mentioned at the very beginning: The forensic aspect of this challenge is what made it so fun for me. Doing this together with my friend really gave me new insight on these kind of interfaces and what can be logged and how. If I would ever would be confronted with a logfile like this from a tablet, phone, laptop or other device I now would have a good understanding on how to replicate the user behavior from those logs.  
On the other hand, from an attacking point of view, I think it's also good to know that these things exist to maybe leverage them into logging user behaviour on devices.

You can find out more about Viktor Dufour and his work here: https://vdweb.lu