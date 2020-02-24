#include "configuration.h"

namespace tob::ebpfpub {
StringErrorOr<UserSettings> parseUserSettings(int argc, char *argv[]) {
  CLI::App application("eBPFTracer");

  UserSettings user_settings;

  std::string tracepoint_list;
  application
      .add_option("-t,--tracepoint_list", tracepoint_list,
                  "A comma separated list of syscall tracepoints")
      ->mandatory(true);

  application.add_option("-b,--buffer_size", user_settings.buffer_size,
                         "Buffer size (global)");

  application.add_option("-c,--buffer_count", user_settings.buffer_count,
                         "Buffer count (global)");

  application.add_option("-p,--perf_size", user_settings.perf_event_array_size,
                         "Size of the perf event array. Expressed as 2^N "
                         "(global, one per CPU core)");

  application.add_option("-e,--event_map_size", user_settings.event_map_size,
                         "Amount of entries in the event map (per tracepoint)");

  application.add_flag("-d,--debug", user_settings.debug,
                       "Dump the LLVM IR before executing the tracer");

  try {
    application.parse(argc, argv);

    std::stringstream stream(tracepoint_list);
    std::string tracepoint_name;
    while (std::getline(stream, tracepoint_name, ',')) {
      user_settings.tracepoint_list.push_back(tracepoint_name);
    }

    return user_settings;

  } catch (const CLI::ParseError &e) {
    std::stringstream standard_output;
    std::stringstream error_output;

    application.exit(e, standard_output, error_output);

    auto message = standard_output.str();
    if (!error_output.str().empty()) {
      message += "\n";
      message += error_output.str();
    }

    return StringError::create(message);
  }
}
} // namespace tob::ebpfpub