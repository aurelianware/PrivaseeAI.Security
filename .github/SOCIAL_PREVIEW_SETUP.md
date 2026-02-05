# Social Preview Image Setup

This guide explains how to set up the social preview image for the PrivaseeAI.Security repository on GitHub.

## About the Image

The social preview image (`social-preview.png`) is an architectural diagram that displays when the repository is shared on social media platforms like Twitter, LinkedIn, or Facebook.

**Image Details:**
- **Dimensions:** 1280×640 pixels (GitHub recommended size)
- **Format:** PNG
- **Size:** ~49KB
- **Location:** `.github/assets/social-preview.png`

**Features Highlighted:**
- PrivaseeAI.Security branding
- Real-Time iOS Threat Detection & Monitoring subtitle
- Architectural diagram showing system components:
  - CLI Interface
  - Threat Orchestrator
  - VPN Integrity Monitor
  - API Abuse Monitor
  - Carrier Compromise Detector
  - Backup Monitor
  - Telegram Alerter
- Key statistics: Battle-Tested, Privacy-First, Real-Time, 196 Tests

## How to Set the Social Preview on GitHub

**Note:** Setting the social preview image requires repository administrator access and must be done through the GitHub web interface.

### Step-by-Step Instructions:

1. **Navigate to Repository Settings**
   - Go to https://github.com/aurelianware/PrivaseeAI.Security
   - Click on the **Settings** tab (requires admin access)

2. **Find the Social Preview Section**
   - Scroll down to the **Social preview** section
   - It's located near the top of the Settings page

3. **Upload the Image**
   - Click **Edit** next to the social preview section
   - Click **Upload an image...**
   - Select the file: `.github/assets/social-preview.png` from your local clone
   - Alternatively, download it from the repository first, then upload it

4. **Verify and Save**
   - Preview the image in the dialog
   - Click **Save** or **Set as preview** to confirm
   - The image should now appear in the Social preview section

### Verification

After uploading, you can verify the social preview is working:

1. **Check the Settings page** - The preview should display in the Social preview section
2. **Share on social media** - Share the repository URL on Twitter, LinkedIn, or Facebook to see the preview in action
3. **Use Twitter Card Validator** - Visit https://cards-dev.twitter.com/validator and enter your repo URL
4. **Use LinkedIn Post Inspector** - Visit https://www.linkedin.com/post-inspector/ and enter your repo URL

## Image Requirements (Reference)

GitHub's requirements for social preview images:

- **Minimum dimensions:** 640×320 pixels
- **Recommended dimensions:** 1280×640 pixels (what we use)
- **Maximum file size:** 1 MB
- **Supported formats:** PNG, JPG, GIF
- **Aspect ratio:** 2:1 (width:height)

Our image meets all these requirements.

## Updating the Image

If you need to update the social preview image in the future:

1. **Regenerate the image** using the Python script (see below)
2. **Replace** `.github/assets/social-preview.png` in the repository
3. **Re-upload** to GitHub following the steps above

### Regenerating the Image

The image was created using Python and Pillow. To recreate or modify it:

```bash
# Install Pillow if needed
pip install Pillow

# Run the generation script
python scripts/generate_social_preview.py

# Or create your own script based on the original
```

The original script used:
- **Background:** GitHub dark theme (#0D1117)
- **Primary color:** GitHub blue (#58A6FF)
- **Secondary color:** GitHub green (#7EE787)
- **Accent color:** GitHub red (#F85149)
- **Purple color:** GitHub purple (#BC8CFF)
- **Font:** DejaVu Sans (Bold for title, Regular for text)

## Troubleshooting

**Issue:** Can't find the Settings tab
- **Solution:** You need repository administrator access. Contact the repository owner.

**Issue:** Image doesn't appear after uploading
- **Solution:** Clear your browser cache and reload. It may take a few minutes to propagate.

**Issue:** Image looks blurry or pixelated
- **Solution:** Ensure you're uploading the full-resolution 1280×640 image, not a scaled-down version.

**Issue:** Image is rejected during upload
- **Solution:** Verify the file is under 1 MB and in PNG, JPG, or GIF format.

## Resources

- [GitHub Docs: Customizing your repository's social media preview](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview)
- [Open Graph Protocol](https://ogp.me/)
- [Twitter Card Validator](https://cards-dev.twitter.com/validator)

## Questions?

If you have questions about the social preview image setup, please:
- Open an issue in the repository
- Contact: support@aurelianware.com
