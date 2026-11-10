# Как менять zerosee самому

Открой папку `~/Projects/zerosee` в VS Code. Перед изменениями посмотри
`git status` и `git diff`, чтобы помнить, что уже изменено.

## Где менять

- Лого, цвет и подпись: `src/banner.hpp`.
- Версия: `project(zerosee VERSION ...)` в `CMakeLists.txt`.
- Общая справка и вывод TCP: `src/main.cpp`.
- Аргументы TCP: `src/cli.cpp`.
- Веб-справка и параметры: `src/web_url.cpp`.
- HTTP/TLS: `src/web_http.cpp`.
- Проверки конфигурации: `src/web_analysis.cpp`.
- Отчёты: `src/web_report.cpp`.

Лого состоит из двух массивов строк: красной Z и остальных букв.
Строки одной буквы должны иметь одинаковую ширину, включая пробелы:
иначе следующие буквы сдвигаются. Меняй по одному месту и сразу смотри результат.
Не удаляй `R"(` и `)"` вокруг строк с обратными слешами: это raw string C++.

## Цикл изменения

1. Измени файл и сохрани Ctrl+S.
2. Собери:

```bash
cd ~/Projects/zerosee
cmake --build build -j 2
```

3. Если сборка завершилась успешно, запускай `zerosee`. Ссылка в PATH уже ведёт
на новый бинарник. Если сборка упала, команда может запустить прежнюю версию.
4. Для изменения логики запускай тесты:

```bash
ctest --test-dir build --output-on-failure
```

5. Посмотри diff, затем добавь только нужные файлы в коммит:

```bash
git diff
git add src/banner.hpp
git commit -m "Refine terminal banner"
git push
```

Эти команды предполагают, что первый коммит и origin уже настроены.
При изменении CMake или зависимостей повтори конфигурацию:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j 2
```

Не добавляй в Git сборку, ключи лаборатории и приватные отчёты:
`build/`, `build-*/`, `lab/.certs/`, `reports/` уже исключены.

## Первая публикация, если GitHub недоступен агенту

Сначала создай пустой репозиторий zerosee в своём аккаунте GitHub.
Не добавляй README через сайт: он уже есть локально. Затем настрой локального
автора и origin (замени значения своими):

```bash
cd ~/Projects/zerosee
git config user.name "ТВОЁ ИМЯ"
git config user.email "ТВОЙ EMAIL ИЛИ GITHUB NOREPLY"
git remote add origin git@github.com:ТВОЙ_ЛОГИН/zerosee.git
```

Из-за ранее найденной ошибки системного SSH-конфига можно задать обход
только для этого репозитория:

```bash
git config core.sshCommand 'ssh -F /dev/null -i /home/zero/.ssh/id_ed25519 -o IdentitiesOnly=yes'
```

Проверь список файлов и создай первый коммит:

```bash
git add .github .gitignore CMakeLists.txt README.md STATUS.md docs lab src tests
git diff --cached --stat
git commit -m "Add zerosee web reconnaissance toolkit"
git push -u origin main
```

Не используй force push для исправления обычной ошибки публикации.
Если origin уже есть, сначала проверь `git remote -v`.
