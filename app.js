'use strict';

const Homey = require('homey');

class AigostarApp extends Homey.App {
  async onInit() {
    this.log('Aigostar (Unofficial) app has been initialized');

    this.homey.flow
      .getActionCard('set_color_temperature_percent')
      .registerRunListener(async (args) => {
        await args.device.triggerSetColorTemperaturePercent(args.percent);
      });
  }
}

module.exports = AigostarApp;
