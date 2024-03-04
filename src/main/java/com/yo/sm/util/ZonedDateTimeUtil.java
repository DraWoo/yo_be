package com.yo.sm.util;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

public class ZonedDateTimeUtil {
    final static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    final static DateTimeFormatter formatYmd = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    final static DateTimeFormatter formatterMinuteGroup = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    public static ZonedDateTime stringToDateTime(String dateTime) {
        return LocalDateTime.parse(dateTime, formatter).atZone(ZoneId.systemDefault());
    }

    public static String dateTimeToString(ZonedDateTime zonedDateTime) {
        return zonedDateTime.format(formatYmd);
    }

    public static ZonedDateTime toZonedDateTimeFromMinuteGroup(String dateHourMinute) {
        return LocalDateTime.parse(dateHourMinute, formatterMinuteGroup).atZone(ZoneId.systemDefault());
    }

    public static String toMinuteGroup(ZonedDateTime dateTime) {
        return dateTime.format(formatterMinuteGroup).substring(0, 11) + "0";
    }

    public static String getTodayWithNoTime() {
        final DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-MM-dd");

        ZonedDateTime nowDT = ZonedDateTime.now();
        return nowDT.format(format);
    }

    public static Map<String, ZonedDateTime> startEndDateTime(String start, String end) {
        int startHour = Integer.parseInt(start.substring(8, 10));
        int startMin = Integer.parseInt(start.substring(10, 12));
        LocalDateTime startDateTime = LocalDate.parse(start, formatterMinuteGroup)
                .atTime(startHour, startMin, 0);


        int endHour = Integer.parseInt(end.substring(8, 10));
        int endMin = Integer.parseInt(end.substring(10, 12));
        LocalDateTime endDateTime = LocalDate.parse(end, formatterMinuteGroup)
                .atTime(endHour, endMin, 0);

        Map<String, ZonedDateTime> dateTime = new HashMap<>();
        dateTime.put("start", ZonedDateTime.of(startDateTime, ZoneId.systemDefault()));
        dateTime.put("end", ZonedDateTime.of(endDateTime, ZoneId.systemDefault()));

        return dateTime;

    }

    public static Map<String, ZonedDateTime> getWeeksDateTime(int minusWeek) {
        ZonedDateTime dateTime = LocalDate.now()
                .minusWeeks(minusWeek).atStartOfDay()
                .atZone(ZoneId.systemDefault());

        Calendar calendar = Calendar.getInstance();
        calendar.set(dateTime.getYear(), dateTime.getMonthValue() - 1, dateTime.getDayOfMonth());
        calendar.setFirstDayOfWeek(Calendar.SUNDAY);
        int dayOfWeek = calendar.get(Calendar.DAY_OF_WEEK) - calendar.getFirstDayOfWeek();

        calendar.add(Calendar.DAY_OF_MONTH, -dayOfWeek);

        ZonedDateTime start = calendar.getTime()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .withHour(0).withMinute(0).withSecond(0);

        calendar.add(Calendar.DAY_OF_MONTH, 6);

        ZonedDateTime end = calendar.getTime()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .withHour(23).withMinute(59).withSecond(59);

        Map<String, ZonedDateTime> weeks = new HashMap<>();
        weeks.put("start", start);
        weeks.put("end", end);

        return weeks;
    }


    public static Map<String, LocalDate> getWeeksDateTime(LocalDate localDate) {

        ZonedDateTime dateTime = localDate
                .atStartOfDay(ZoneId.systemDefault());

        Calendar calendar = Calendar.getInstance();
        calendar.set(dateTime.getYear(), dateTime.getMonthValue() - 1, dateTime.getDayOfMonth());
        calendar.setFirstDayOfWeek(Calendar.SUNDAY);
        int dayOfWeek = calendar.get(Calendar.DAY_OF_WEEK) - calendar.getFirstDayOfWeek();

        calendar.add(Calendar.DAY_OF_MONTH, -dayOfWeek);

        ZonedDateTime start = calendar.getTime()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .withHour(0).withMinute(0).withSecond(0);

        calendar.add(Calendar.DAY_OF_MONTH, 6);

        ZonedDateTime end = calendar.getTime()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .withHour(23).withMinute(59).withSecond(59);

        Map<String, LocalDate> weeks = new HashMap<>();
        weeks.put("start", start.toLocalDate());
        weeks.put("end", end.toLocalDate());

        return weeks;
    }


    public static ZonedDateTime start(String date) {
        LocalDateTime dt = LocalDate.parse(date, DateTimeFormatter.ISO_DATE)
                .atStartOfDay();
        return ZonedDateTime.of(dt, ZoneId.systemDefault());
    }


    public static ZonedDateTime get(LocalDate localDate, LocalTime localTime) {
        return localDate.atTime(localTime).atZone(ZoneId.systemDefault());
    }

    public static ZonedDateTime end(String date) {
        LocalDateTime dt = LocalDate.parse(date, DateTimeFormatter.ISO_DATE)
                .atTime(23, 59, 59);
        return ZonedDateTime.of(dt, ZoneId.systemDefault());
    }

    public static Map<String, ZonedDateTime> getStartEnd(LocalDate localDate, int dayAgo) {
        ZonedDateTime start = localDate.now()
                .minusDays(dayAgo).atStartOfDay()
                .atZone(ZoneId.systemDefault());

        ZonedDateTime end = localDate.atStartOfDay(ZoneId.systemDefault())
                .withHour(23).withMinute(59).withSecond(59);

        Map<String, ZonedDateTime> date = new HashMap<>();
        date.put("start", start);
        date.put("end", end);

        return date;
    }

    public static Map<String, ZonedDateTime> getTodayDateTime(LocalDate localDate) {

        ZonedDateTime dateTime = localDate != null ? localDate.atStartOfDay(ZoneId.systemDefault()) :
                LocalDateTime.now()
                        .atZone(ZoneId.systemDefault());

        ZonedDateTime start = dateTime.withHour(0)
                .withMinute(0).withSecond(0);

        ZonedDateTime end = dateTime.withHour(23).withMinute(59).withSecond(59);

        Map<String, ZonedDateTime> today = new HashMap<>();
        today.put("start", start);
        today.put("end", end);

        return today;
    }

}