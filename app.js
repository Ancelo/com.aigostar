'use strict';

const Homey = require('homey');

// Named colors -> hue in degrees (full saturation).
const COLOR_HUE = {
  red: 0, orange: 30, yellow: 55, green: 120,
  cyan: 180, blue: 220, purple: 275, pink: 320,
};

class AigostarApp extends Homey.App {
  async onInit() {
    this.log('Aigostar app has been initialized');

    this.homey.flow.getActionCard('set_color_temperature_percent')
      .registerRunListener(async (args) => args.device.triggerSetColorTemperaturePercent(args.percent));

    this.homey.flow.getActionCard('set_color')
      .registerRunListener(async (args) => {
        const hueDeg = COLOR_HUE[args.color];
        if (hueDeg === undefined) throw new Error(`Unknown color: ${args.color}`);
        await args.device.flowSetColor(hueDeg / 360, 1);
      });

    this.homey.flow.getActionCard('random_color')
      .registerRunListener(async (args) => args.device.flowRandomColor());
  }
}

module.exports = AigostarApp;
