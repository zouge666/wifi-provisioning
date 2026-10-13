# How to add a device to a Wi-Fi network

Use this guide when you have the device and a phone in your hands. You need:

- the device, with the sticker on it
- a phone with a camera and a browser
- the name and the password of the Wi-Fi network that the device must join

## Steps

1. Turn on the device. If it has no Wi-Fi, it makes its own Wi-Fi after about 30 seconds. The name is `wifiprov-` and the ID on the sticker. It stays on for 10 minutes.
2. Connect your phone to that Wi-Fi. It has no password. Your phone may say there is no internet. Stay connected. The page comes from the device, not from the internet.
3. Scan the QR code on the sticker with your phone camera and open the link. The page shows the Wi-Fi networks that the device can see. If the camera does not open the link, open `http://10.42.0.1:8080` in your browser. Then paste the text that is printed next to the QR code.
4. Pick your network and type its password. If you do not see your network, tap **Not listed? Type its name** and type the name. Then tap **Join**.
5. The page says the details are sent. The device leaves its own Wi-Fi to join yours, so the page stops working. Connect your phone back to your normal Wi-Fi.
6. Wait one minute and look at your Wi-Fi list. If you see `wifiprov-` and the ID again, the device could not join. Connect to it again and tap **Check result**. The page tells you why. If you closed the page, scan the QR code and try again.

Your password is encrypted on your phone before it is sent. Nobody can read it from the air.

## If it does not work

| What you see | What to do |
| --- | --- |
| You do not see `wifiprov-…` in your Wi-Fi list | Wait one minute after you turn on the device. It only makes its Wi-Fi when it has no other network, and only for 10 minutes. Turn the device off and on to try again. |
| The camera does not open the link | Open `http://10.42.0.1:8080` in your browser and paste the text next to the QR code. |
| The page says it cannot reach the device | Check that your phone is still on the Wi-Fi of the device. Some phones leave a Wi-Fi that has no internet and use mobile data. Turn mobile data off and stay on the Wi-Fi of the device. |
| The device did not accept the setup code | Check the text on the sticker. After 5 wrong codes, the device locks for 5 minutes. |
| The device is busy | Another phone is talking to it. Wait a moment and try again. |
| The network did not accept the password | Check the password and try again. |
| The device cannot see the network | Move the device closer to the network. Check the name too. |
