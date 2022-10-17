# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
            'error': {
                'format': 'Error!'
            },
            "hi2c": {
                'format': '{{data.data}}'
            }
        }
        
    
    temp_frame = None
    frame_bytes = None
    isSHTFrame = False
    isSHTReadFrame = False

    def crc8(self, data):
        crc = 0xFF
        for iByte in range(len(data)):
            crc = (crc ^ data[iByte]) & 0xFF
            for iBit in range(8):
                if ((crc & 0x80) == 0x80):
                    crc = ((crc << 1) ^ 0x31) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        return crc

    def checkCRC(self, data):
        return self.crc8(data[0:2]) == data[2]

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        pass

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # set our frame to an error frame, which will eventually get over-written as we get data.
        if self.temp_frame is None:
            self.temp_frame = AnalyzerFrame("error", frame.start_time, frame.end_time, {
                    "address": "error",
                    "data": "",
                }
            )
            self.frame_bytes = []

        if frame.type == "start" or (frame.type == "address" and self.temp_frame.type == "error"):
            self.temp_frame = AnalyzerFrame("hi2c", frame.start_time, frame.end_time, {
                    "data": "",
                }
            )            
            self.frame_bytes = []

        if frame.type == "address":            
            self.isSHTReadFrame = frame.data["read"]
            if (frame.data["address"][0] != 112):
                self.isSHTFrame = False
            else:
                self.isSHTFrame = True


        if frame.type == "data":
            self.frame_bytes.append(frame.data["data"][0])

        if frame.type == "stop":
            if (self.isSHTFrame):
                self.temp_frame.end_time = frame.end_time
                if (self.isSHTReadFrame):
                    if (len(self.frame_bytes) == 6):
                        if (self.checkCRC(self.frame_bytes[0:3]) == True):
                            humidity = self.frame_bytes[0] << 8 | self.frame_bytes[1]
                            humidity = 100 * (humidity / 65536)
                        else:
                            humidity = None

                        if (self.checkCRC(self.frame_bytes[3:6]) == True):
                            temperature = self.frame_bytes[3] << 8 | self.frame_bytes[4]
                            temperature = -45 + 175 * (temperature / 65536)
                        else:
                            temperature = None

                        if (temperature == None or humidity == None):
                            self.temp_frame.data["data"] = "CRC error"
                        else:
                            self.temp_frame.data["data"] = "RH: " + str(round(humidity, 2)) + " Temp: " + str(round(temperature, 2)) + " °C"

                    elif (len(self.frame_bytes) == 2):
                        readID = self.frame_bytes[0] << 8 | self.frame_bytes[1]
                        self.temp_frame.data["data"] = "SHT identifier: " + str(((readID >> 5) & 1) | (readID & 0x3F))
                    else:
                        self.temp_frame.data["address"] = "error"
                        self.temp_frame.data["data"] = "Invalid number of bytes: " + self.frame_bytes
                        
                else:
                    commandName = ""
                    if (len(self.frame_bytes) == 2):
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x3517:
                            commandName = "Wakeup"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0xB098:
                            commandName = "Sleep"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x805D:
                            commandName = "Software reset"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0xEFC8:
                            commandName = "Read ID register"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x7CA2:
                            commandName = "Read normal mode, measure temperature first with clock stretching enabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x5C24:
                            commandName = "Read normal mode, measure RH first with clock stretching enabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x7866:
                            commandName = "Read normal mode, measure temperature first with clock stretching disabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x58E0:
                            commandName = "Read normal mode, measure RH first with clock stretching disabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x6458:
                            commandName = "Read low power mode, measure temperature first with clock stretching enabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x44DE:
                            commandName = "Read low power mode, measure RH first with clock stretching enabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x609C:
                            commandName = "Read low power mode, measure temperature first with clock stretching disabled"
                        if (self.frame_bytes[0] << 8 | self.frame_bytes[1]) == 0x401A:
                            commandName = "Read low power mode, measure RH first with clock stretching disabled"
                    if commandName == "":
                        if (len(self.frame_bytes) != 2):
                            self.temp_frame.data["data"] = "Invalid command: unexpected number of bytes read, expected 2 got " + str(len(self.frame_bytes))
                        else:
                            self.temp_frame.data["data"] = "Invalid command: " + hex((self.frame_bytes[0] << 8 | self.frame_bytes[1]))
                    else:
                        self.temp_frame.data["data"] = "Command: " + commandName
                new_frame = self.temp_frame
                self.temp_frame = None
                self.frame_bytes = None
                return new_frame
